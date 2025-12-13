from __future__ import annotations
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from typing import Optional, Tuple, Set
from datetime import datetime
import time
from random import gammavariate
import platform
import subprocess

import typer
from InquirerPy import inquirer
import keyring
import json
import logging
from pathlib import Path

app = typer.Typer(help="경희대 중앙도서관 CLI")

SERVICE = "libgo"  
ID_KEY = "default_id"    

MOBILE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
)

ROOMS = {
    8: "1F 제1열람실",
    9: "2F 제2열람실",
    10: "1F      벗터",
    11: "2F      혜윰",
}

HYEYUM_SINGLE_SEAT_NUMBERS = {
    *[str(i) for i in range(1, 28)],
    *[str(i) for i in range(166, 188)],
}

RESERVE_INTERVAL_SHAPE = 4
RESERVE_INTERVAL_SCALE = 0.25
RESERVE_INTERVAL_MIN = 0.25



def _sleep() -> None:
    time.sleep(
        gammavariate(RESERVE_INTERVAL_SHAPE, RESERVE_INTERVAL_SCALE)
        + RESERVE_INTERVAL_MIN
    )


def _notify(title: str, message: str) -> None:
    """터미널에서 작업이 끝났을 때 OS 알림을 띄웁니다.

    - macOS: osascript(Notification Center)
    - Linux: notify-send
    - 그 외/실패 시: 터미널 벨 + 로그만 남김

    알림 실패는 프로그램 흐름을 막지 않습니다.
    """
    try:
        # 1) 터미널 벨 (가능하면 항상)
        try:
            print("\a", end="", flush=True)
        except Exception:
            pass

        system = platform.system().lower()

        if system == "darwin":
            # macOS Notification Center
            # osascript -e 'display notification "message" with title "title"'
            msg_esc = message.replace('"', '\\"')
            title_esc = title.replace('"', '\\"')
            script = f'display notification "{msg_esc}" with title "{title_esc}"'
            subprocess.run(["osascript", "-e", script], check=False)
            return

        if system == "linux":
            # notify-send가 있으면 사용
            subprocess.run(["notify-send", title, message], check=False)
            return

        # Windows 등: 기본 구현은 벨/출력으로 대체
        _log("NOTIFY", "notification fallback", title=title, message=message)

    except Exception as e:
        _log("NOTIFY", "notification failed", level="warning", error=str(e), title=title)

WAITING_BAR = ["|", "/", "-", "\\"]

LOG_DIR = Path(".libgo")
LOG_FILE = LOG_DIR / "libgo.log"


def _get_logger() -> logging.Logger:
    logger = logging.getLogger("libgo")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger



LOGGER = _get_logger()

SESSION_COOKIE: Optional[str] = None


CURRENT_STD_ID: Optional[str] = None

def _set_current_user(std_id: str) -> None:
    """현재 CLI 세션에서 사용 중인 학번을 전역 컨텍스트로 저장합니다."""
    global CURRENT_STD_ID
    CURRENT_STD_ID = std_id


def _log(kind: str, message: str, level: str = "info", **fields: object) -> None:
    """일관된 포맷으로 로그를 남기기 위한 헬퍼.

    kind: [MENU], [CMD], [HTTP/GET], [HTTP/POST], [SERVER], [LOGIN] 등의 태그용 문자열
    message: 핵심 설명 메시지
    level: info / warning / error
    fields: 추가로 붙이고 싶은 key=value 쌍
    """
    user = CURRENT_STD_ID or "-"
    fields_str = " ".join(f"{k}={v}" for k, v in fields.items() if v is not None)
    line = f"[{kind}] user={user} {message}"
    if fields_str:
        line += f" | {fields_str}"

    if level == "warning":
        LOGGER.warning(line)
    elif level == "error":
        LOGGER.error(line)
    else:
        LOGGER.info(line)


def _log_http(method: str, phase: str, url: str, status: Optional[int] = None, **fields: object) -> None:
    """HTTP 요청/응답을 일관된 포맷으로 로깅합니다.

    method: GET/POST 등
    phase: request/response 구분용 텍스트
    url: 호출 URL
    status: 응답 코드 (요청 시에는 None 가능)
    """
    kind = f"HTTP/{method.upper()}"
    msg = f"{phase} {url}"
    _log(kind, msg, status=status, **fields)


def _get_or_login_cookie(std_id: str, password: str) -> Optional[str]:
    """캐시된 세션 쿠키가 있으면 그대로 사용하고, 없으면 로그인 절차를 거쳐 쿠키를 생성합니다."""
    global SESSION_COOKIE
    _set_current_user(std_id)
    if SESSION_COOKIE:
        return SESSION_COOKIE

    cookie = _perform_login(std_id, password)
    if cookie:
        SESSION_COOKIE = cookie
    return cookie


def _ua() -> str:
    return MOBILE_UA

def _save_credentials(std_id: str, password: str) -> None:
    try:
        keyring.set_password(SERVICE, ID_KEY, std_id)
        keyring.set_password(SERVICE, std_id, password)
    except (keyring.errors.PasswordSetError, keyring.errors.KeyringLocked, keyring.errors.KeyringError) as e:
        typer.secho(f"keyring에 자격 증명 저장 실패: {e}", fg=typer.colors.RED)
        raise

def _get_credentials() -> Optional[Tuple[str, Optional[str]]]:
    try:
        std_id = keyring.get_password(SERVICE, ID_KEY)
        if not std_id:
            return None
        pw = keyring.get_password(SERVICE, std_id)
        return std_id, pw
    except Exception:
        return None

def _delete_credentials() -> bool:
    """
    keyring에 저장된 학번/비밀번호가 존재했는지 여부를 반환합니다.
    - 저장된 학번이 있으면 삭제를 시도하고 True를 반환합니다.
    - 저장된 학번이 없으면 False를 반환합니다.
    삭제 중 예외는 조용히 무시합니다.
    """
    try:
        std_id = keyring.get_password(SERVICE, ID_KEY)
        if not std_id:
            return False

        # 1) 학번에 매핑된 비밀번호 삭제
        try:
            keyring.delete_password(SERVICE, std_id)
        except keyring.errors.PasswordDeleteError:
            # 이미 삭제되었거나 존재하지 않는 경우 무시
            pass

        # 2) 기본 학번 키 삭제
        try:
            keyring.delete_password(SERVICE, ID_KEY)
        except keyring.errors.PasswordDeleteError:
            # 이미 삭제되었거나 존재하지 않는 경우 무시
            pass

        return True
    except Exception:
        # 삭제 실패 케이스는 드물다고 가정하고, 조용히 "없음"으로 처리
        return False

def _login_wizard() -> Optional[Tuple[str, str]]:
    try:
        std_id = inquirer.text(
            message="[중앙도서관] 학번을 입력하세요:",
            qmark="[?]",
            validate=lambda x: len(x.strip()) > 0 or "학번은 필수입니다.",
        ).execute()
        password = inquirer.secret(
            message="[중앙도서관] 비밀번호를 입력하세요:",
            qmark="[?]",
            validate=lambda x: len(x) > 0 or "비밀번호는 필수입니다.",
        ).execute()

        _set_current_user(std_id.strip())
        return std_id.strip(), password
    except KeyboardInterrupt:
        typer.secho("\nCancelled by user", fg=typer.colors.YELLOW)
        return None

@app.command()
def menu() -> None:
    """중앙도서관 CLI 인터랙티브 메뉴"""
    try:
        while True:
            choice = inquirer.select(
                message="메뉴 선택 (↕:이동, Enter:선택)",
                choices=[
                    "내 좌석 정보",
                    "좌석 현황 조회",
                    "1인석 예매 대기",
                    "좌석 예약",
                    "좌석 연장",
                    "좌석 퇴실",
                    "로그인",
                    "로그아웃",
                    "종료",
                ],
                default="내 좌석 정보",
                qmark="[?]",
                pointer=">",
            ).execute()

            _log("MENU", "choice", choice=choice)

            if choice == "내 좌석 정보":
                status()
            elif choice == "좌석 현황 조회":
                seats()
            elif choice == "1인석 예매 대기":
                wait_single_seat()
            elif choice == "좌석 예약":
                reserve()
            elif choice == "좌석 연장":
                extend()
            elif choice == "좌석 퇴실":
                leave()
            elif choice == "로그인":
                creds = _get_credentials()
                from_keyring = creds is not None

                # keyring에 정보가 없으면 마법사로부터 새 자격 증명 입력
                if not creds:
                    creds = _login_wizard()

                # 사용자가 입력을 취소했거나 유효한 정보가 없는 경우
                if not creds:
                    typer.secho("로그인이 취소되었거나 로그인 정보가 없습니다.", fg=typer.colors.YELLOW)
                    continue

                std_id, password = creds
                cookie = _get_or_login_cookie(std_id, password)
                if cookie:
                    if from_keyring:
                        typer.secho(f"이미 로그인되어 있습니다. (학번: {std_id})", fg=typer.colors.GREEN)
                    else:
                        # 로그인 성공한 경우에만 자격 증명 저장
                        _save_credentials(std_id.strip(), password)
                        typer.secho("로그인 성공! 아이디 비밀번호를 안전하게 저장했습니다.", fg=typer.colors.GREEN)
                else:
                    typer.secho("로그인 실패: 아이디 또는 비밀번호가 올바르지 않습니다.", fg=typer.colors.RED)
            elif choice == "로그아웃":
                logout()
            elif choice == "종료":
                raise typer.Exit(0)
            else:
                typer.echo("아직 구현되지 않은 항목입니다.")
    except KeyboardInterrupt:
        typer.secho("\nAborted!", fg=typer.colors.RED)
@app.command()
def status() -> None:
    """
    LibSeat 내 좌석 현황(마이페이지) 정보를 출력합니다.
    """
    try:
        _log("CMD", "status", command="status")
        credentials = _get_credentials()
        if not credentials:
            typer.secho("로그인이 필요합니다. 먼저 로그인 메뉴에서 로그인하세요.", fg=typer.colors.YELLOW)
            return
        std_id, password = credentials
        cookie = _get_or_login_cookie(std_id, password)
        if not cookie:
            typer.secho("로그인 실패: 쿠키를 얻을 수 없습니다.", fg=typer.colors.RED)
            raise typer.Exit(1)
        res = requests.get(
            "https://libseat.khu.ac.kr/user/my-status",
            headers={
                "Cookie": cookie,
                "User-Agent": _ua(),
                "Accept": "application/json",
            },
            verify=False,
        )
        res.raise_for_status()
        try:
            data = res.json()
        except Exception as e:
            typer.secho(f"JSON 파싱 오류: {e}", fg=typer.colors.RED)
            typer.echo(res.text)
            raise typer.Exit(1)

        # LOGGER.info(f"status raw data: {json.dumps(data, ensure_ascii=False)[:1000]}")

        my_seat = data.get("data", {}).get("mySeat")
        if not my_seat:
            typer.echo("현재 이용 중인 좌석이 없습니다.")
            return

        # LOGGER.info(f"status mySeat: {json.dumps(my_seat, ensure_ascii=False)}")

        seat = my_seat.get("seat", {})
        seat_name = seat.get("name", "알 수 없음")
        group = seat.get("group", {})
        room_name = group.get("name", "알 수 없음")
        class_group = group.get("classGroup", {})
        campus_name = class_group.get("name", "알 수 없음")

        enter_time_ms = my_seat.get("inTime")
        expire_time_ms = my_seat.get("expireTime")
        confirm_time_ms = my_seat.get("confirmTime")
        count_down_time_ms = my_seat.get("countDownTime")
        out_time_ms = my_seat.get("outTime")
        state = my_seat.get("state")

        def format_time(ms: int) -> str:
            return datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M")

        _log(
            "STATUS",
            "mySeat parsed",
            seatCode=seat.get("code")
            or seat.get("seatCode")
            or seat.get("id")
            or seat.get("seatId"),
            state=state,
            room=room_name,
            seat=seat_name,
        )

        confirm_time_str = format_time(confirm_time_ms) if confirm_time_ms else "알 수 없음"
        count_down_time_str = format_time(count_down_time_ms) if count_down_time_ms else "알 수 없음"
        enter_time_str = format_time(enter_time_ms) if enter_time_ms else "알 수 없음"
        expire_time_str = format_time(expire_time_ms) if expire_time_ms else "알 수 없음"

        # 상태 문자열 매핑: 서버 state 값과 inTime(outTime) 필드가 항상 동시에 채워지지 않는 케이스가 있어
        # outTime/expireTime 등을 함께 참고해 표시한다.
        if out_time_ms:
            status_str = "퇴실 또는 종료"
        elif state == 0 and enter_time_ms is None:
            status_str = "입실 대기(예약 완료)"
        elif state == 5:
            # 일부 케이스에서 state=5인데 inTime이 비어있을 수 있음
            status_str = "이용 중"
        else:
            status_str = f"상태 미확인(state={state})"

        # 남은 시간 및 마감(입실 마감/만료) 정보 계산
        now_ts = time.time()
        deadline_label: Optional[str] = None
        deadline_time_ms: Optional[int] = None
        remaining_minutes: Optional[int] = None

        # 입실 전이면 입실 마감 시간, 입실 후면 만료 시간을 기준으로 삼는다.
        if state == 0 and enter_time_ms is None and count_down_time_ms:
            deadline_label = "입실 마감"
            deadline_time_ms = count_down_time_ms
        elif expire_time_ms:
            deadline_label = "만료"
            deadline_time_ms = expire_time_ms

        deadline_line = None
        if deadline_label and deadline_time_ms:
            remaining_minutes = int((deadline_time_ms / 1000 - now_ts) / 60)
            if remaining_minutes < 0:
                remaining_minutes = 0
            deadline_time_str = format_time(deadline_time_ms)
            # 예: "입실 마감  : 2025-11-24 20:49 (23분 남음)"
            deadline_line = f"{deadline_label}  : {deadline_time_str} ({remaining_minutes}분 남음)"

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

        typer.secho(f"\n=== 📚 내 좌석 정보 ({now_str} 기준) ===", fg=typer.colors.CYAN, bold=True)

        # 기본 정보
        lines = [
            f"캠퍼스     : {campus_name}",
            f"열람실     : {room_name}",
            f"좌석 번호  : {seat_name}",
            f"예약 시간  : {confirm_time_str}",
        ]
        lines.append(f"상태 코드  : {state}")

        # 실제 입실한 경우에만 입실 시간 표기
        if state == 5 and enter_time_ms:
            lines.append(f"입실 시간  : {enter_time_str}")

        # 상태는 항상 표시
        lines.append(f"상태       : {status_str}")

        for line in lines:
            typer.echo(line)

        # 입실 마감/만료 라인은 색상으로 강조해서 출력
        if deadline_line is not None and remaining_minutes is not None:
            # 남은 시간에 따라 색상 구분 (5분 이내: 빨강, 15분 이내: 노랑, 그 외: 초록)
            if remaining_minutes <= 5:
                color = typer.colors.RED
            elif remaining_minutes <= 15:
                color = typer.colors.YELLOW
            else:
                color = typer.colors.GREEN
            typer.secho(deadline_line, fg=color, bold=True)
        elif deadline_line is not None:
            # 남은 시간을 계산하지 못했을 때는 기본 색상으로만 표시
            typer.secho(deadline_line, bold=True)

    except typer.Exit:
        raise
    except Exception as e:
        typer.secho("좌석 정보를 불러오는 중 오류가 발생했습니다.", fg=typer.colors.RED)

@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    """
    스크립트를 서브커맨드 없이 실행했을 때,
    자동으로 로그인(쿠키 확보)을 시도한 뒤 메뉴를 보여줍니다.
    """
    if ctx.invoked_subcommand is None:
        # 1) 자동 로그인 시도
        try:
            creds = _get_credentials()
            from_keyring = creds is not None
            _log("CMD", "root entry", command="_root", from_keyring=from_keyring)

            # keyring에 저장된 정보가 없으면 로그인 마법사로 입력받기
            if not creds:
                creds = _login_wizard()

            if creds:
                std_id, password = creds
                _set_current_user(std_id)
                cookie = _get_or_login_cookie(std_id, password)

                if cookie and not from_keyring:
                    _log("LOGIN", "auto login success (fresh)", std_id=std_id)
                    # 처음 로그인에 성공한 경우 자격 증명 저장
                    _save_credentials(std_id.strip(), password)
                    typer.secho(
                        "자동 로그인 성공! 아이디와 비밀번호를 안전하게 저장했습니다.",
                        fg=typer.colors.GREEN,
                    )
                elif cookie and from_keyring:
                    _log("LOGIN", "auto login success (from keyring)", std_id=std_id)
                    typer.secho(
                        f"저장된 학번({std_id})으로 자동 로그인되었습니다.",
                        fg=typer.colors.GREEN,
                    )
                else:
                    _log("LOGIN", "auto login failed", std_id=std_id)
                    typer.secho(
                        "자동 로그인 실패: 아이디 또는 비밀번호가 올바르지 않습니다.",
                        fg=typer.colors.RED,
                    )
            else:
                _log("LOGIN", "auto login skipped (no creds)")
                # 사용자가 마법사를 취소한 경우 등
                typer.secho(
                    "자동 로그인을 건너뛰고 메뉴로 이동합니다.",
                    fg=typer.colors.YELLOW,
                )
        except KeyboardInterrupt:
            _log("LOGIN", "auto login cancelled")
            typer.secho("\n자동 로그인이 취소되었습니다.", fg=typer.colors.YELLOW)
        except Exception as e:
            _log("LOGIN", "auto login error", level="error", error=str(e))
            typer.secho(
                f"자동 로그인 중 오류가 발생했습니다: {e}",
                fg=typer.colors.RED,
            )

        # 2) 로그인 시도 후 메뉴 진입
        menu()

@app.command()
def seats() -> None:
    """
    중앙도서관 열람실별 남은 좌석 수를 실시간으로 표시합니다.
    """
    try:
        _log("CMD", "seats", command="seats")
        credentials = _get_credentials()
        if not credentials:
            typer.secho("로그인이 필요합니다. 먼저 로그인 메뉴에서 로그인하세요.", fg=typer.colors.YELLOW)
            return

        std_id, password = credentials
        cookie = _get_or_login_cookie(std_id, password)
        if not cookie:
            typer.secho("로그인 실패: 쿠키를 얻을 수 없습니다.", fg=typer.colors.RED)
            raise typer.Exit(1)

        typer.secho("\n=== 🪑 실시간 열람실 좌석 현황 ===\n", fg=typer.colors.CYAN, bold=True)

        for room_id in [8, 10, 11, 9]:
            room_name = ROOMS[room_id]
            url = f"https://libseat.khu.ac.kr/libraries/seats/{room_id}"
            res = requests.get(
                url,
                headers={
                    "Cookie": cookie,
                    "User-Agent": _ua(),
                    "Accept": "application/json",
                },
                verify=False,
            )
            _log_http("GET", "request/response", url, status=res.status_code, room_id=room_id)

            if res.status_code != 200:
                typer.secho(f"[{room_name}] 조회 실패 ({res.status_code})", fg=typer.colors.RED)
                continue

            seats_data = res.json().get("data", [])
            total = len(seats_data)
            available = sum(1 for s in seats_data if s.get("seatTime") is None)
            available_percent = (available / total) * 100 if total > 0 else 0.0
            _log(
                "SEATS",
                "room summary",
                room=room_name,
                total=total,
                available=available,
                available_percent=f"{available_percent:.1f}",
            )
            typer.echo(f"[{room_name}] {available:>4} / {total:<4} ({int(round(available_percent))}%)")

            # 혜윰 1인석은 별도로 한 줄 더 보여준다(구역 구분 없이 합산)
            if room_id == 11:
                def _sname(s: dict) -> str:
                    return str(s.get("name") or s.get("seatNo") or s.get("num") or "")

                single_seats = [s for s in seats_data if _sname(s) in HYEYUM_SINGLE_SEAT_NUMBERS]
                total_single = len(single_seats)
                available_single = sum(1 for s in single_seats if s.get("seatTime") is None)
                single_percent = (available_single / total_single) * 100 if total_single > 0 else 0.0

                _log(
                    "SEATS",
                    "hyeyum single seats summary",
                    room=room_name,
                    total_single=total_single,
                    available_single=available_single,
                    available_percent=f"{single_percent:.1f}",
                )

                # API 데이터 기준으로 매칭되는 1인석이 한 개 이상 있을 때만 출력
                if total_single > 0:
                    typer.echo(
                        typer.style(
                            f"  └     1인석  {available_single:>4} / {total_single:<4} ({int(round(single_percent))}%)",
                            fg=typer.colors.BRIGHT_CYAN,
                            bold=True,
                        )
                    )

    except KeyboardInterrupt:
        typer.secho("\nCancelled by user", fg=typer.colors.YELLOW)
    except typer.Exit:
        raise
    except Exception as e:
        _log("SEATS", "error", level="error", error=str(e))
        typer.secho(f"좌석 정보를 불러오는 중 오류가 발생했습니다: {e}", fg=typer.colors.RED)


def _find_available_hyeyum_single_seat(
    cookie: str,
    excluded_seat_ids: Optional[Set[str]] = None,
) -> Optional[Tuple[str, str]]:
    """혜윰 1인석 중 현재 예약 가능한 좌석을 찾아 (seat_id, seat_no) 반환.

    excluded_seat_ids에 포함된 seatId는 후보에서 제외한다.
    """
    room_id = 11
    url = f"https://libseat.khu.ac.kr/libraries/seats/{room_id}"
    res = requests.get(
        url,
        headers={
            "Cookie": cookie,
            "User-Agent": _ua(),
            "Accept": "application/json",
        },
        verify=False,
    )
    _log_http("GET", "request/response", url, status=res.status_code, room_id=room_id)

    if res.status_code != 200:
        _log("SEATS", "hyeyum single seats fetch failed", level="warning", status=res.status_code)
        return None

    try:
        seats_data = res.json().get("data", [])
    except Exception as e:
        _log("SEATS", "hyeyum single seats json parse failed", level="warning", error=str(e))
        return None

    def _sid(s: dict) -> Optional[str]:
        v = s.get("id") or s.get("seatId") or s.get("code") or s.get("seatCode")
        return str(v) if v is not None else None

    def _sname(s: dict) -> str:
        return str(s.get("name") or s.get("seatNo") or s.get("num") or "")

    excluded = excluded_seat_ids or set()

    candidates = [
        s for s in seats_data
        if s.get("seatTime") is None
        and _sname(s) in HYEYUM_SINGLE_SEAT_NUMBERS
        and _sid(s) is not None
        and _sid(s) not in excluded
    ]

    if not candidates:
        return None

    def _seat_sort_key(s: dict) -> int:
        name = _sname(s)
        try:
            return int(name)
        except Exception:
            return 10**9

    candidates.sort(key=_seat_sort_key)
    seat = candidates[0]
    seat_id = _sid(seat)
    seat_no = _sname(seat)

    if not seat_id or not seat_no:
        return None

    return seat_id, seat_no


# === 내부 헬퍼 함수 추가 ===
def _fetch_my_seat(cookie: str) -> Optional[dict]:
    """현재 계정의 mySeat 정보를 조회해 반환합니다. 없으면 None."""
    status_url = "https://libseat.khu.ac.kr/user/my-status"
    try:
        res = requests.get(
            status_url,
            headers={
                "Cookie": cookie,
                "User-Agent": _ua(),
                "Accept": "application/json",
            },
            verify=False,
        )
        _log_http("GET", "request/response", status_url, status=res.status_code)
        if res.status_code != 200:
            return None
        try:
            data = res.json()
        except Exception:
            return None
        return data.get("data", {}).get("mySeat")
    except Exception as e:
        _log("STATUS", "fetch mySeat failed", level="warning", error=str(e))
        return None


def _resolve_seat_code_from_myseat(my_seat: dict) -> Optional[str]:
    """mySeat 응답에서 퇴실 API에 필요한 seatCode를 최대한 유연하게 추출합니다."""
    seat = my_seat.get("seat", {}) or {}
    seat_code = (
        seat.get("code")
        or seat.get("seatCode")
        or seat.get("id")
        or seat.get("seatId")
        or my_seat.get("seatCode")
    )
    if seat_code is None:
        return None
    return str(seat_code)


def _leave_current_seat(cookie: str, *, silent: bool = True) -> bool:
    """현재 이용/예약 중인 좌석이 있으면 자동 퇴실 처리합니다.

    - 좌석이 없으면 True
    - 퇴실 성공 시 True
    - 퇴실 실패 시 False

    silent=True면 사용자에게는 최소한의 메시지만 출력합니다.
    """
    my_seat = _fetch_my_seat(cookie)
    if not my_seat:
        return True

    seat = my_seat.get("seat", {}) or {}
    group = seat.get("group") or my_seat.get("group") or {}

    seat_name = (
        seat.get("name")
        or seat.get("seatNo")
        or seat.get("num")
        or "알 수 없음"
    )
    room_name = group.get("name", "알 수 없음")

    seat_code = _resolve_seat_code_from_myseat(my_seat)
    if not seat_code:
        _log("LEAVE", "auto leave failed: missing seatCode", level="warning")
        if not silent:
            typer.secho("현재 좌석의 코드(seatCode)를 찾을 수 없습니다.", fg=typer.colors.RED)
        return False

    _log(
        "LEAVE",
        "auto leave start",
        seat=seat_name,
        room=room_name,
        seatCode=seat_code,
    )

    if not silent:
        typer.secho("\n=== 자동 퇴실 ===", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"열람실     : {room_name}")
        typer.echo(f"좌석 번호  : {seat_name}")
        typer.echo(f"seatCode   : {seat_code}")

    leave_url = f"https://libseat.khu.ac.kr/libraries/leave/{seat_code}"
    try:
        leave_res = requests.post(
            leave_url,
            headers={
                "Cookie": cookie,
                "User-Agent": _ua(),
                "Accept": "application/json",
            },
            verify=False,
        )
        _log_http("POST", "request/response", leave_url, status=leave_res.status_code, seatCode=seat_code)

        success = False
        msg = ""
        code = None

        try:
            body = leave_res.json()
            code = body.get("code")
            msg = body.get("msg") or body.get("message") or ""
            _log("SERVER", "auto leave result", code=code, msg=msg)
            if code == 1 or str(code) == "1":
                success = True
        except Exception:
            # JSON이 아니더라도 2xx면 성공으로 간주
            if 200 <= leave_res.status_code < 300:
                success = True

        if success:
            _log("LEAVE", "auto leave success", seatCode=seat_code)
            if not silent:
                typer.secho("퇴실 처리 성공!", fg=typer.colors.GREEN, bold=True)
            return True

        _log("LEAVE", "auto leave failed", level="warning", seatCode=seat_code, code=code, msg=msg)
        if not silent:
            if msg:
                typer.secho(f"퇴실 처리 실패: {msg}", fg=typer.colors.RED)
            else:
                typer.secho("퇴실 처리에 실패했습니다.", fg=typer.colors.RED)
        return False

    except Exception as e:
        _log("LEAVE", "auto leave error", level="error", error=str(e), seatCode=seat_code)
        if not silent:
            typer.secho(f"퇴실 처리 중 오류가 발생했습니다: {e}", fg=typer.colors.RED)
        return False


@app.command()
def wait_single_seat() -> None:
    """
    혜윰 1인석이 비워질 때까지 대기하면서 자동으로 예약을 시도합니다.
    - 대기 간격은 Gamma(α=4, β=0.25) + 최소 0.25초를 사용합니다.
    - 성공 시 예약 결과와 함께 status()를 한 번 출력합니다.
    """
    try:
        _log("CMD", "wait_single_seat", command="wait_single_seat")
        credentials = _get_credentials()
        if not credentials:
            typer.secho("로그인이 필요합니다. 먼저 로그인 메뉴에서 로그인하세요.", fg=typer.colors.YELLOW)
            return

        std_id, password = credentials
        cookie = _get_or_login_cookie(std_id, password)
        if not cookie:
            typer.secho("로그인 실패: 쿠키를 얻을 수 없습니다.", fg=typer.colors.RED)
            raise typer.Exit(1)

        minutes_str = inquirer.text(
            message="혜윰 1인석 이용 시간(분)을 입력하세요:",
            qmark="[?]",
            default="240",
            validate=lambda x: (x.isdigit() and int(x) > 0) or "양의 정수를 입력하세요.",
        ).execute()
        minutes = int(minutes_str)
        _log("RESERVE", "wait_single_seat minutes input", minutes=minutes)

        typer.secho("\n=== ⏳ 혜윰 1인석 예매 대기 시작 ===", fg=typer.colors.CYAN, bold=True)
        typer.echo("빈 1인석이 감지되면 자동으로 예약을 시도합니다.")

        start_ts = time.time()
        excluded_seat_ids: Set[str] = set()

        attempt = 0
        while True:
            attempt += 1
            found = _find_available_hyeyum_single_seat(cookie, excluded_seat_ids)

            if not found:
                elapsed = int(time.time() - start_ts)
                hours = elapsed // 3600
                minutes_ = (elapsed % 3600) // 60
                seconds = elapsed % 60

                typer.echo(
                    f"\r예매 대기 중... {WAITING_BAR[attempt & 3]} 시도: {attempt:4d} ({hours:02d}:{minutes_:02d}:{seconds:02d}) ",
                    nl=False,
                )
                _sleep()
                continue

            seat_id, seat_no = found
            _log("RESERVE", "hyeyum single seat found", seat_no=seat_no, seat_id=seat_id, attempt=attempt)
            typer.secho(
                f"\n✅ 혜윰 1인석 {seat_no}번 발견 — 예약 시도 중...",
                fg=typer.colors.GREEN,
                bold=True,
            )

            url = "https://libseat.khu.ac.kr/libraries/seat"
            res = requests.post(
                url,
                headers={
                    "Cookie": cookie,
                    "User-Agent": _ua(),
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json={"seatId": seat_id, "time": minutes},
                verify=False,
            )
            _log_http("POST", "request/response", url, status=res.status_code, seatId=seat_id, minutes=minutes)

            try:
                data = res.json()
            except Exception:
                data = {}

            code = data.get("code")
            msg = data.get("msg") or data.get("message") or ""
            _log("SERVER", "wait_single_seat reserve result", code=code, msg=msg, seat_no=seat_no, seat_id=seat_id)

            if code == 1:
                typer.secho("좌석 예약/사용 시작 성공!", fg=typer.colors.GREEN, bold=True)
                typer.echo(f"좌석 번호: {seat_no}")
                _notify("libgo 좌석 예약 성공", f"혜윰 1인석 {seat_no}번 ({minutes}분)")
                try:
                    status()
                except Exception:
                    pass
                break

            # 1206: 이미 다른 좌석을 이용 중인 상태로 추정
            # - 좌석이 실제로 비워졌을 때에만 퇴실해야 하므로, 1206이 뜬 경우에만 자동 퇴실을 시도한다.
            # - 퇴실 성공 시, 방금 발견한 동일 좌석에 대해 즉시 1회 재예약을 시도한다.
            if code == 1206:
                _log(
                    "RESERVE",
                    "reserve rejected with 1206; attempting auto leave then immediate retry",
                    seat_no=seat_no,
                    seat_id=seat_id,
                )
                typer.secho(
                    "현재 다른 좌석을 이용/예약 중이라 예약이 거절되었습니다(1206). 동일 좌석 예약을 위해 자동 퇴실 후 즉시 재시도합니다.",
                    fg=typer.colors.YELLOW,
                )

                left_ok = _leave_current_seat(cookie, silent=True)
                if not left_ok:
                    typer.secho(
                        "자동 퇴실에 실패해 동일 좌석 재예약을 진행할 수 없습니다. 계속 대기합니다.",
                        fg=typer.colors.YELLOW,
                    )
                    _sleep()
                    continue

                # 퇴실 직후 동일 좌석에 대해 1회 즉시 재시도
                retry_res = requests.post(
                    url,
                    headers={
                        "Cookie": cookie,
                        "User-Agent": _ua(),
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                    json={"seatId": seat_id, "time": minutes},
                    verify=False,
                )
                _log_http(
                    "POST",
                    "request/response",
                    url,
                    status=retry_res.status_code,
                    seatId=seat_id,
                    minutes=minutes,
                    retry="after_leave",
                )

                try:
                    retry_data = retry_res.json()
                except Exception:
                    retry_data = {}

                retry_code = retry_data.get("code")
                retry_msg = retry_data.get("msg") or retry_data.get("message") or ""
                _log(
                    "SERVER",
                    "wait_single_seat reserve retry result",
                    code=retry_code,
                    msg=retry_msg,
                    seat_no=seat_no,
                    seat_id=seat_id,
                )

                if retry_code == 1:
                    typer.secho("좌석 예약/사용 시작 성공!", fg=typer.colors.GREEN, bold=True)
                    typer.echo(f"좌석 번호: {seat_no}")
                    _notify("libgo 좌석 예약 성공", f"혜윰 1인석 {seat_no}번 ({minutes}분)")
                    try:
                        status()
                    except Exception:
                        pass
                    break

                # 재시도에서도 1209가 뜨면 이번 대기에서 제외
                if retry_code == 1209:
                    excluded_seat_ids.add(str(seat_id))
                    _log(
                        "RESERVE",
                        "exclude seat due to 1209 after retry",
                        seat_no=seat_no,
                        seat_id=seat_id,
                    )
                    typer.secho(
                        f"{seat_no}번 좌석은 재예약 제한(1209)으로 이번 대기에서 제외합니다.",
                        fg=typer.colors.YELLOW,
                    )
                    _sleep()
                    continue

                # 그 외 실패는 메시지 간결 출력 후 다시 대기
                if retry_msg and str(retry_msg).strip().upper() != "SUCCESS":
                    typer.secho(f"재시도 예약 실패: {retry_msg}", fg=typer.colors.YELLOW)
                else:
                    typer.secho("재시도 예약 실패. 다시 대기합니다.", fg=typer.colors.YELLOW)

                _sleep()
                continue

            # 1209: 동일 좌석 재배정 대기 제한 등으로 추정 — 해당 좌석은 이번 대기에서 제외
            if code == 1209:
                excluded_seat_ids.add(str(seat_id))
                _log(
                    "RESERVE",
                    "exclude seat due to 1209",
                    seat_no=seat_no,
                    seat_id=seat_id,
                )
                typer.secho(
                    f"{seat_no}번 좌석은 재예약 제한(1209)으로 이번 대기에서 제외합니다.",
                    fg=typer.colors.YELLOW,
                )
                _sleep()
                continue

            # 기타 실패는 불필요한 메시지 노이즈를 줄여 간결 출력
            if msg and str(msg).strip().upper() != "SUCCESS":
                typer.secho(f"예약 실패: {msg}", fg=typer.colors.YELLOW)
            else:
                typer.secho("예약 실패. 다시 대기합니다.", fg=typer.colors.YELLOW)

            _sleep()

    except KeyboardInterrupt:
        typer.secho("\nCancelled by user", fg=typer.colors.YELLOW)
    except typer.Exit:
        raise
    except Exception as e:
        _log("RESERVE", "wait_single_seat error", level="error", error=str(e))
        typer.secho(f"1인석 예매 대기 중 오류가 발생했습니다: {e}", fg=typer.colors.RED)

def _pick_seat(cookie: str) -> Optional[str]:
    """열람실을 먼저 고르고, 해당 열람실의 *빈 좌석* 목록에서 좌석을 선택해 seatId를 반환합니다."""
    # 1) 열람실 선택
    room_choice = inquirer.select(
        message="어느 열람실에서 예약할까요?",
        choices=[f"{rid} — {name}" for rid, name in ROOMS.items()],
        qmark="[?]",
        pointer=">",
    ).execute()
    _log("MENU", "pick_seat room", choice=room_choice)
    try:
        room_id = int(room_choice.split(" — ")[0])
        _log("MENU", "pick_seat room parsed", room_id=room_id)
    except Exception:
        typer.secho("열람실 선택 파싱 실패", fg=typer.colors.RED)
        return None

    # 2) 해당 열람실 좌석 목록 조회
    url = f"https://libseat.khu.ac.kr/libraries/seats/{room_id}"
    res = requests.get(
        url,
        headers={
            "Cookie": cookie,
            "User-Agent": _ua(),
            "Accept": "application/json",
        },
        verify=False,
    )
    if res.status_code != 200:
        typer.secho(f"[{ROOMS.get(room_id, room_id)}] 좌석 목록 조회 실패 ({res.status_code})", fg=typer.colors.RED)
        return None

    try:
        seats_data = res.json().get("data", [])
        _log("SEATS", "seats loaded", room_id=room_id, count=len(seats_data))
    except Exception as e:
        typer.secho(f"좌석 목록 JSON 파싱 실패: {e}", fg=typer.colors.RED)
        typer.echo(res.text)
        return None

    # 3) 빈 좌석만 필터링하고, 좌석 표기용 이름/아이디 필드 유연 처리
    def _sid(s: dict):
        return s.get("id") or s.get("seatId") or s.get("code") or s.get("seatCode")

    def _sname(s: dict):
        return s.get("name") or s.get("seatNo") or s.get("num") or str(_sid(s))

    available = [s for s in seats_data if s.get("seatTime") is None]
    _log("SEATS", "available seats", room_id=room_id, count=len(available))
    if not available:
        typer.secho(f"[{ROOMS.get(room_id, room_id)}] 현재 예약 가능한 좌석이 없습니다.", fg=typer.colors.YELLOW)
        return None

    choices = [
        f"{_sname(s)} (id:{_sid(s)})" for s in available if _sid(s) is not None
    ]
    if not choices:
        # 디버깅 도움: 좌석 객체의 키를 한 건 출력
        typer.secho("좌석 객체에서 seatId를 찾지 못했습니다. 샘플 키를 출력합니다:", fg=typer.colors.RED)
        if seats_data:
            typer.echo(", ".join(sorted(seats_data[0].keys())))
        return None

    picked = inquirer.select(
        message="예약할 좌석을 선택하세요",
        choices=choices,
        qmark="[?]",
        pointer=">",
        default=choices[0],
    ).execute()

    # '... (id:1234)'에서 id만 추출
    m = re.search(r"id:(\d+)", picked)
    if not m:
        typer.secho("좌석 선택 파싱 실패", fg=typer.colors.RED)
        _log("SEATS", "pick_seat parse failure", picked=picked)
        return None
    seat_id = m.group(1)
    _log("SEATS", "seat picked", picked=picked, seat_id=seat_id)
    return seat_id

# 새 헬퍼 함수: _pick_seat_by_number
def _pick_seat_by_number(cookie: str) -> Optional[str]:
    """
    열람실을 먼저 고르고, 사용자가 보는 좌석 번호(예: 76)를 입력받아
    해당 좌석의 seatId를 찾아 반환합니다.
    - 현재 예약 가능한(빈) 좌석 중에서만 검색합니다.
    """
    # 1) 열람실 선택
    room_choice = inquirer.select(
        message="어느 열람실에서 예약할까요?",
        choices=[f"{rid} — {name}" for rid, name in ROOMS.items()],
        qmark="[?]",
        pointer=">",
    ).execute()
    _log("MENU", "pick_seat_by_number room", choice=room_choice)
    try:
        room_id = int(room_choice.split(" — ")[0])
        _log("MENU", "pick_seat_by_number room parsed", room_id=room_id)
    except Exception:
        typer.secho("열람실 선택 파싱 실패", fg=typer.colors.RED)
        return None

    # 2) 해당 열람실 좌석 목록 조회
    url = f"https://libseat.khu.ac.kr/libraries/seats/{room_id}"
    res = requests.get(
        url,
        headers={
            "Cookie": cookie,
            "User-Agent": _ua(),
            "Accept": "application/json",
        },
        verify=False,
    )
    if res.status_code != 200:
        typer.secho(f"[{ROOMS.get(room_id, room_id)}] 좌석 목록 조회 실패 ({res.status_code})", fg=typer.colors.RED)
        return None

    try:
        seats_data = res.json().get("data", [])
        _log("SEATS", "seats loaded", room_id=room_id, count=len(seats_data))
    except Exception as e:
        typer.secho(f"좌석 목록 JSON 파싱 실패: {e}", fg=typer.colors.RED)
        typer.echo(res.text)
        return None

    def _sid(s: dict):
        return s.get("id") or s.get("seatId") or s.get("code") or s.get("seatCode")

    def _sname(s: dict):
        return s.get("name") or s.get("seatNo") or s.get("num") or str(_sid(s))

    # 3) 좌석 번호 입력
    seat_no = inquirer.text(
        message="예약할 좌석 번호를 입력하세요 (예: 76):",
        qmark="[?]",
        validate=lambda x: len(x.strip()) > 0 or "좌석 번호는 필수입니다.",
    ).execute().strip()
    _log("SEATS", "seat number input", room_id=room_id, seat_no=seat_no)

    # 4) 현재 예약 가능한 좌석 중에서 번호 일치하는 좌석 찾기
    available = [s for s in seats_data if s.get("seatTime") is None]
    _log("SEATS", "available seats", room_id=room_id, count=len(available))

    matches = [s for s in available if str(_sname(s)) == seat_no]
    # 전체 좌석 중 해당 번호가 있는지(단지 사용 중일 뿐인지)를 확인
    all_matches = [s for s in seats_data if str(_sname(s)) == seat_no]
    if not matches:
        reason_msg = f"{seat_no}번 좌석은 현재 예약 가능하지 않습니다."
        if all_matches:
            # 좌석은 존재하지만 seatTime 등이 차 있어 예약 불가한 경우
            seat_obj = all_matches[0]
            seat_time = seat_obj.get("seatTime") or {}
            my_seat_flag = seat_time.get("mySeat")
            _log("SEATS", "seat exists but not available", room_id=room_id, seat_no=seat_no)
            # mySeat 플래그로 현재 로그인한 사용자가 점유 중인지 구분
            if my_seat_flag:
                reason_msg = (
                    f"{seat_no}번 좌석은 이미 현재 계정으로 이용 중입니다.\n"
                )
            else:
                reason_msg = (
                    f"{seat_no}번 좌석은 이미 다른 사용자가 이용 중입니다.\n"
                )
        else:
            _log("SEATS", "seat number not found", room_id=room_id, seat_no=seat_no)
            reason_msg = (
                f"{seat_no}번 좌석은 존재하지 않거나 선택할 수 없는 좌석입니다.\n"
            )
        typer.secho(reason_msg, fg=typer.colors.YELLOW)
        return None

    seat = matches[0]
    seat_id = _sid(seat)
    if not seat_id:
        typer.secho("선택한 좌석에서 seatId를 찾을 수 없습니다.", fg=typer.colors.RED)
        return None

    seat_id_str = str(seat_id)
    _log("SEATS", "seat resolved", room_id=room_id, seat_no=seat_no, seat_id=seat_id_str)
    return seat_id_str

@app.command()
def reserve() -> None:
    """
    특정 좌석을 지정 시간(분) 만큼 사용(예약)합니다.
    POST https://libseat.khu.ac.kr/libraries/seat
    요청 바디: {"seatId": <좌석 코드>, "time": <분>}
    성공 판단: 응답 JSON의 code === 1
    """
    try:
        _log("CMD", "reserve", command="reserve")
        credentials = _get_credentials()
        if not credentials:
            typer.secho("로그인이 필요합니다. 먼저 로그인 메뉴에서 로그인하세요.", fg=typer.colors.YELLOW)
            return

        std_id, password = credentials
        cookie = _get_or_login_cookie(std_id, password)
        if not cookie:
            typer.secho("로그인 실패: 쿠키를 얻을 수 없습니다.", fg=typer.colors.RED)
            raise typer.Exit(1)

        mode = inquirer.select(
            message="좌석 선택 방법을 고르세요",
            choices=["열람실에서 선택", "좌석 번호 직접 입력"],
            qmark="[?]",
            pointer=">",
        ).execute()
        _log("RESERVE", "mode selected", mode=mode)

        if mode == "열람실에서 선택":
            seat_id = _pick_seat(cookie) or ""
        else:
            # 열람실을 선택한 뒤, 사용자가 보는 좌석 번호(예: 76)를 입력받아 seatId를 해석한다.
            seat_id = _pick_seat_by_number(cookie) or ""

        _log("RESERVE", "seat_id resolved", seat_id=seat_id)

        if not seat_id:
            # 상위 선택 단계(_pick_seat / _pick_seat_by_number)에서 이미 사용자에게 메시지를 보여줬으므로
            # 여기서는 조용히 함수만 종료한다.
            return

        minutes_str = inquirer.text(
            message="이용 시간(분)을 입력하세요:",
            qmark="[?]",
            default="240",
            validate=lambda x: (x.isdigit() and int(x) > 0) or "양의 정수를 입력하세요.",
        ).execute()
        minutes = int(minutes_str)
        _log("RESERVE", "minutes input", minutes=minutes)

        url = "https://libseat.khu.ac.kr/libraries/seat"
        res = requests.post(
            url,
            headers={
                "Cookie": cookie,
                "User-Agent": _ua(),
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={"seatId": seat_id, "time": minutes},
            verify=False,
        )
        _log_http("POST", "request/response", url, status=res.status_code, seatId=seat_id, minutes=minutes)

        try:
            data = res.json()
        except Exception:
            typer.secho("응답 파싱 실패. 서버 응답:", fg=typer.colors.RED)
            typer.echo(res.text)
            raise typer.Exit(1)

        code = data.get("code")
        msg = data.get("msg") or data.get("message") or ""
        _log("SERVER", "reserve result", code=code, msg=msg)

        # LibSeat 응답 의미:
        # - code == 1   : 정상적으로 좌석 사용 시작(또는 예약) 성공
        # - 그 외 숫자  : 에러 코드 (이미 사용 중, 시간 제한, 권한 부족 등)
        success = (code == 1)

        if success:
            typer.secho("좌석 예약/사용 시작 성공!", fg=typer.colors.GREEN, bold=True)
            typer.echo(f"seatId={seat_id}, time={minutes}분")
            _notify("libgo 좌석 예약 성공", f"seatId={seat_id} ({minutes}분)")
            if msg:
                typer.echo(f"서버 메시지: {msg}")
            # 정확한 만료 시각(expireTime)을 확인하기 위해 한 번 status()를 호출한다.
            try:
                LOGGER.info("reserve success: calling status() once to refresh expireTime")
                status()
            except Exception:
                LOGGER.warning(
                    "reserve success: status() call failed (expireTime cache may be stale)",
                    exc_info=True,
                )
        else:
            # LibSeat에서 자주 나오는 특정 에러 코드는 별도 메시지로 처리
            if code == 1206:
                # 이미 다른 좌석을 이용 중인 상태에서 새 좌석을 시작하려는 경우로 추정
                typer.secho(
                    "이미 이용 중인 좌석이 있습니다.",
                    fg=typer.colors.YELLOW,
                )
                LOGGER.info(
                    "reserve special case 1206 (already using other seat): raw=%s",
                    json.dumps(data, ensure_ascii=False),
                )
            elif code == 1209:
                # 모바일 앱에서는 "동일 좌석 재배정 대기 중입니다."로 표기되는 상황으로 추정
                # (퇴실 직후 동일 좌석을 다시 잡을 때 등)
                typer.secho(
                    "동일 좌석 재배정 대기 중입니다.",
                    fg=typer.colors.YELLOW,
                )
                LOGGER.info(
                    "reserve special case 1209 (same seat reassignment pending): raw=%s",
                    json.dumps(data, ensure_ascii=False),
                )
            else:
                typer.secho("좌석 예약 실패. 잠시 후 다시 시도해 보세요.", fg=typer.colors.RED)
                LOGGER.warning(
                    "reserve failed: code=%s, msg=%s, raw=%s",
                    code,
                    msg,
                    json.dumps(data, ensure_ascii=False),
                )


    except KeyboardInterrupt:
        typer.secho("\nCancelled by user", fg=typer.colors.YELLOW)
    except typer.Exit:
        # Typer가 처리하도록 그대로 전달
        raise
    except Exception as e:
        _log("RESERVE", "error", level="error", error=str(e))
        typer.secho(f"좌석 예약 중 오류가 발생했습니다: {e}", fg=typer.colors.RED)


# 좌석 연장 명령 추가

@app.command()
def extend() -> None:
    """
    현재 이용(또는 입실 대기) 중인 좌석의 이용 시간을 연장합니다.

    POST https://libseat.khu.ac.kr/libraries/seat-extension
    요청 바디:
      {
        "code": <좌석 코드>,
        "groupCode": <열람실 그룹 코드>,
        "time": <연장 시간(분)>,
        "beacon": [{"major": 1, "minor": 1}]
      }

    성공 판단(레퍼런스 구현 기준):
      - 응답 JSON의 data == 1
      - 또는 code == 1 을 성공으로 간주(서버 구현 차이 대비)
    """
    try:
        _log("CMD", "extend", command="extend")
        credentials = _get_credentials()
        if not credentials:
            typer.secho("로그인이 필요합니다. 먼저 로그인 메뉴에서 로그인하세요.", fg=typer.colors.YELLOW)
            return

        std_id, password = credentials
        cookie = _get_or_login_cookie(std_id, password)
        if not cookie:
            typer.secho("로그인 실패: 쿠키를 얻을 수 없습니다.", fg=typer.colors.RED)
            raise typer.Exit(1)

        # 1) 현재 mySeat 정보 조회
        status_url = "https://libseat.khu.ac.kr/user/my-status"
        res = requests.get(
            status_url,
            headers={
                "Cookie": cookie,
                "User-Agent": _ua(),
                "Accept": "application/json",
            },
            verify=False,
        )
        _log_http("GET", "request/response", status_url, status=res.status_code)
        res.raise_for_status()

        try:
            data = res.json()
        except Exception as e:
            typer.secho(f"JSON 파싱 오류: {e}", fg=typer.colors.RED)
            typer.echo(res.text)
            raise typer.Exit(1)

        my_seat = data.get("data", {}).get("mySeat")
        if not my_seat:
            typer.secho("현재 이용 중이거나 예약된 좌석이 없습니다.", fg=typer.colors.YELLOW)
            return

        seat = my_seat.get("seat", {}) or {}
        group = seat.get("group") or my_seat.get("group") or {}

        # 좌석 코드(서버에서 code로 요구)
        seat_code = (
            seat.get("code")
            or seat.get("seatCode")
            or seat.get("id")
            or seat.get("seatId")
            or my_seat.get("seatCode")
        )

        # 열람실 그룹 코드(레퍼런스 서버에서 groupCode로 전달)
        group_code = (
            group.get("code")
            or group.get("groupCode")
            or group.get("id")
            or my_seat.get("groupCode")
        )

        seat_name = (
            seat.get("name")
            or seat.get("seatNo")
            or seat.get("num")
            or "알 수 없음"
        )
        room_name = group.get("name", "알 수 없음")

        if not seat_code or not group_code:
            _log(
                "EXTEND",
                "missing seat_code or group_code",
                level="warning",
                seatCode=seat_code,
                groupCode=group_code,
            )
            typer.secho(
                "연장에 필요한 좌석 코드 또는 열람실 그룹 코드를 찾을 수 없습니다.",
                fg=typer.colors.RED,
            )
            return

        _log(
            "EXTEND",
            "target seat resolved",
            seatCode=str(seat_code),
            groupCode=str(group_code),
            seat=seat_name,
            room=room_name,
        )

        typer.secho("\n=== ⏱ 좌석 연장 ===", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"열람실     : {room_name}")
        typer.echo(f"좌석 번호  : {seat_name}")
        typer.echo(f"seatCode   : {seat_code}")
        typer.echo(f"groupCode  : {group_code}")

        # 2) 연장 시간 입력
        minutes_str = inquirer.text(
            message="연장할 시간(분)을 입력하세요:",
            qmark="[?]",
            default="240",
            validate=lambda x: (x.isdigit() and int(x) > 0) or "양의 정수를 입력하세요.",
        ).execute()
        minutes = int(minutes_str)
        _log("EXTEND", "minutes input", minutes=minutes)

        # 3) 연장 API 호출
        extend_url = "https://libseat.khu.ac.kr/libraries/seat-extension"
        payload = {
            "code": str(seat_code),
            "groupCode": str(group_code),
            "time": minutes,
            "beacon": [
                {"major": 1, "minor": 1}
            ],
        }

        extend_res = requests.post(
            extend_url,
            headers={
                "Cookie": cookie,
                "User-Agent": _ua(),
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json=payload,
            verify=False,
        )
        _log_http("POST", "request/response", extend_url, status=extend_res.status_code, seatCode=seat_code, groupCode=group_code, minutes=minutes)

        try:
            body = extend_res.json()
        except Exception:
            body = {}

        code = body.get("code")
        msg = body.get("msg") or body.get("message") or ""
        data_flag = body.get("data")

        _log(
            "SERVER",
            "extend result",
            code=code,
            msg=msg,
            data=data_flag,
            seatCode=str(seat_code),
            groupCode=str(group_code),
            minutes=minutes,
        )

        success = False
        # 레퍼런스 서버 구현: data == 1
        if data_flag == 1 or str(data_flag) == "1":
            success = True
        # 서버 구현 차이 대비: code == 1 도 성공으로 간주
        if code == 1 or str(code) == "1":
            success = True
        # JSON이 비어도 HTTP 2xx면 성공 가능성 고려
        if not body and 200 <= extend_res.status_code < 300:
            success = True

        if success:
            typer.secho("좌석 연장 성공!", fg=typer.colors.GREEN, bold=True)
            if msg and str(msg).strip().upper() != "SUCCESS":
                typer.echo(f"서버 메시지: {msg}")
            # 연장 후 상태 새로고침
            try:
                status()
            except Exception:
                pass
        else:
            if msg:
                typer.secho(f"좌석 연장 실패: {msg}", fg=typer.colors.YELLOW)
            else:
                typer.secho("좌석 연장에 실패했습니다.", fg=typer.colors.RED)

    except KeyboardInterrupt:
        typer.secho("\nCancelled by user", fg=typer.colors.YELLOW)
    except typer.Exit:
        raise
    except Exception as e:
        _log("EXTEND", "error", level="error", error=str(e))
        typer.secho(f"좌석 연장 중 오류가 발생했습니다: {e}", fg=typer.colors.RED)

@app.command()
def whoami() -> None:
    """키링에 저장된 기본 학번을 확인합니다."""
    pair = _get_credentials()
    if not pair:
        typer.secho("저장된 로그인 정보가 없습니다. `libgo login`을 실행하세요.", fg=typer.colors.YELLOW)
        raise typer.Exit(1)
    std_id, pw = pair
    _set_current_user(std_id)
    _log("CMD", "whoami", std_id=std_id, has_password=bool(pw))
    typer.echo(f"현재 기본 학번: {std_id}")
    typer.echo("비밀번호: 저장됨" if pw else "비밀번호: (없음)")

@app.command()
def logout() -> None:
    """키링에 저장된 학번/비밀번호를 삭제합니다."""
    _log("CMD", "logout")
    if _delete_credentials():
        typer.secho("저장된 로그인 정보를 삭제했습니다.", fg=typer.colors.GREEN)
    else:
        typer.secho("저장된 로그인 정보가 없습니다.", fg=typer.colors.YELLOW)

    global SESSION_COOKIE
    SESSION_COOKIE = None
    _set_current_user("")

def main() -> None:
    app()

def _perform_login(std_id: str, password: str) -> Optional[str]:
    _set_current_user(std_id)
    _log("LOGIN", "perform_login start", std_id=std_id)
    try:
        session = requests.Session()

        # 1. 공개키 가져오기
        login_url = "https://lib.khu.ac.kr/login"
        res = session.get(
            login_url,
            headers={"User-Agent": _ua()},
            verify=False,
        )
        _log_http("GET", "request/response", login_url, status=res.status_code)
        cookie = res.headers.get("Set-Cookie", "")
        match = re.search(r"encrypt\.setPublicKey\('([^']+)'", res.text)
        if not match:
            _log("LOGIN", "public key not found", level="error")
            typer.secho("공개키를 가져올 수 없습니다.", fg=typer.colors.RED)
            return None

        pub_key = match.group(1)
        rsa_key = RSA.importKey(f"-----BEGIN PUBLIC KEY-----\n{pub_key}\n-----END PUBLIC KEY-----")
        cipher = PKCS1_v1_5.new(rsa_key)
        enc_id = base64.b64encode(cipher.encrypt(std_id.encode())).decode()
        enc_pw = base64.b64encode(cipher.encrypt(password.encode())).decode()

        # 2. 중앙도서관 로그인
        login_post_url = "https://lib.khu.ac.kr/login"
        res = session.post(
            login_post_url,
            data={"encId": enc_id, "encPw": enc_pw, "autoLoginChk": "N"},
            headers={"Cookie": cookie, "User-Agent": _ua()},
            verify=False,
            allow_redirects=True,
        )
        _log_http("POST", "request/response", login_post_url, status=res.status_code)
        # 로그인 실패 여부는 호출한 쪽에서 메시지를 출력하도록, 여기서는 단순히 실패만 반환
        if '<p class="userName">' not in res.text:
            _log("LOGIN", "perform_login failed (userName marker not found)", level="warning")
            return None

        lib_cookie = "; ".join([f"{k}={v}" for k, v in session.cookies.get_dict().items()])

        # 3. mid_user_id 가져오기
        mid_url = "https://lib.khu.ac.kr/relation/mobileCard"
        res_mid = session.get(
            mid_url,
            headers={"Cookie": lib_cookie, "User-Agent": _ua()},
            verify=False,
        )
        _log_http("GET", "request/response", mid_url, status=res_mid.status_code)
        match_mid = re.search(r'name="mid_user_id" value="([^"]+)"', res_mid.text)
        if not match_mid:
            _log("LOGIN", "mid_user_id not found", level="error")
            typer.secho("❌ mid_user_id를 가져올 수 없습니다.", fg=typer.colors.RED)
            return None
        mid_user_id = match_mid.group(1)

        # 4. LibSeat 로그인
        seat_login_url = "https://libseat.khu.ac.kr/login_library"
        seat_res = session.post(
            seat_login_url,
            data={"STD_ID": std_id},
            headers={"Cookie": lib_cookie, "User-Agent": _ua()},
            verify=False,
            allow_redirects=False,
        )
        _log_http("POST", "request/response", seat_login_url, status=seat_res.status_code, STD_ID=std_id)

        libseat_cookie = seat_res.headers.get("Set-Cookie")

        if not libseat_cookie:
            _log("LOGIN", "libseat cookie missing", level="warning", status=seat_res.status_code)
            typer.secho(f"❌ LibSeat 로그인 실패 (상태 코드 {seat_res.status_code}) — 쿠키 없음", fg=typer.colors.RED)
            return lib_cookie

        combined_cookie = f"{lib_cookie}; {libseat_cookie}"
        _log("LOGIN", "perform_login success")
        return combined_cookie

    except Exception as e:
        _log("LOGIN", "perform_login error", level="error", error=str(e))
        typer.secho(f"로그인 요청 중 오류 발생: {e}", fg=typer.colors.RED)
        return None

if __name__ == "__main__":
    main()
@app.command()
def leave() -> None:
    """현재 이용 중인 좌석을 퇴실 처리합니다."""
    try:
        _log("CMD", "leave", command="leave")
        credentials = _get_credentials()
        if not credentials:
            typer.secho("로그인이 필요합니다. 먼저 로그인 메뉴에서 로그인하세요.", fg=typer.colors.YELLOW)
            return

        std_id, password = credentials
        cookie = _get_or_login_cookie(std_id, password)
        if not cookie:
            typer.secho("로그인 실패: 쿠키를 얻을 수 없습니다.", fg=typer.colors.RED)
            raise typer.Exit(1)

        # 1) 현재 mySeat 정보 조회
        status_url = "https://libseat.khu.ac.kr/user/my-status"
        res = requests.get(
            status_url,
            headers={
                "Cookie": cookie,
                "User-Agent": _ua(),
                "Accept": "application/json",
            },
            verify=False,
        )
        _log_http("GET", "request/response", status_url, status=res.status_code)
        res.raise_for_status()

        try:
            data = res.json()
        except Exception as e:
            typer.secho(f"JSON 파싱 오류: {e}", fg=typer.colors.RED)
            typer.echo(res.text)
            raise typer.Exit(1)

        # LOGGER.info(f"leave my-status raw: {json.dumps(data, ensure_ascii=False)[:1000]}")

        my_seat = data.get("data", {}).get("mySeat")
        if not my_seat:
            typer.secho("현재 이용 중인 좌석이 없습니다.", fg=typer.colors.YELLOW)
            return

        seat = my_seat.get("seat", {}) or {}
        seat_name = (
            seat.get("name")
            or seat.get("seatNo")
            or seat.get("num")
            or "알 수 없음"
        )

        # group 정보는 seat 안에 있지 않을 수도 있어 mySeat 쪽도 함께 확인
        group = seat.get("group") or my_seat.get("group") or {}
        room_name = group.get("name", "알 수 없음")
        class_group = group.get("classGroup", {})
        campus_name = class_group.get("name", "알 수 없음")

        seat_code = (
            seat.get("code")
            or seat.get("seatCode")
            or seat.get("id")
            or seat.get("seatId")
        )
        if not seat_code:
            try:
                LOGGER.info(
                    "leave: cannot find seatCode, seat obj=%s",
                    json.dumps(seat, ensure_ascii=False),
                )
            except Exception:
                LOGGER.info("leave: cannot find seatCode, seat obj (json dump failed)")
            typer.secho("현재 좌석의 코드(seatCode)를 찾을 수 없습니다.", fg=typer.colors.RED)
            return

        _log(
            "LEAVE",
            "current seat",
            campus=campus_name,
            room=room_name,
            seat=seat_name,
            seatCode=seat_code,
        )

        typer.secho("\n=== 퇴실 대상 좌석 ===", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"캠퍼스     : {campus_name}")
        typer.echo(f"열람실     : {room_name}")
        typer.echo(f"좌석 번호  : {seat_name}")
        typer.echo(f"seatCode   : {seat_code}")

        # 사용자 확인
        confirm = inquirer.confirm(
            message="위 좌석을 정말 퇴실 처리할까요?",
            default=True,
            qmark="[?]",
        ).execute()
        _log("LEAVE", "confirm", confirm=confirm)
        if not confirm:
            typer.secho("퇴실을 취소했습니다.", fg=typer.colors.YELLOW)
            return

        # 2) 실제 퇴실 API 호출 (공용 헬퍼 사용)
        success = _leave_current_seat(cookie, silent=False)
        if success:
            typer.secho("퇴실 처리 성공!", fg=typer.colors.GREEN, bold=True)
        else:
            typer.secho("퇴실 처리에 실패했습니다.", fg=typer.colors.RED)

    except KeyboardInterrupt:
        typer.secho("\nCancelled by user", fg=typer.colors.YELLOW)
    except typer.Exit:
        # Typer가 처리하도록 그대로 전달
        raise
    except Exception as e:
        _log("LEAVE", "error", level="error", error=str(e))
        typer.secho(f"퇴실 처리 중 오류가 발생했습니다: {e}", fg=typer.colors.RED)