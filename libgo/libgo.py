from __future__ import annotations
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from typing import Optional, Tuple, Dict
from datetime import datetime
import time

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

# 마지막으로 확인한 좌석별 예약 종료 시각(ms). 동일 좌석 재예약 제한(1209) 안내에 사용된다.
LAST_SEAT_EXPIRE: Dict[str, int] = {}


def _get_or_login_cookie(std_id: str, password: str) -> Optional[str]:
    """캐시된 세션 쿠키가 있으면 그대로 사용하고, 없으면 로그인 절차를 거쳐 쿠키를 생성합니다."""
    global SESSION_COOKIE
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
                    "로그인",
                    "내 좌석 정보",
                    "실시간 좌석 현황",
                    "좌석 예약",
                    "퇴실",
                    "로그아웃",
                    "나가기",
                ],
                default="로그인",
                qmark="[?]",
                pointer=">",
            ).execute()

            LOGGER.info(f"menu choice: {choice}")

            if choice == "로그인":
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
            elif choice == "내 좌석 정보":
                status()
            elif choice == "실시간 좌석 현황":
                seats()
            elif choice == "좌석 예약":
                reserve()
            elif choice == "퇴실":
                leave()
            elif choice == "로그아웃":
                logout()
            elif choice == "나가기":
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
        LOGGER.info("status command called")
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

        LOGGER.info(f"status raw data: {json.dumps(data, ensure_ascii=False)[:1000]}")

        my_seat = data.get("data", {}).get("mySeat")
        if not my_seat:
            typer.echo("현재 이용 중인 좌석이 없습니다.")
            return

        LOGGER.info(f"status mySeat: {json.dumps(my_seat, ensure_ascii=False)}")

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

        # 동일 좌석 재예약 제한(1209) 안내를 위해 마지막으로 본 종료 시각을 캐시한다.
        seat_code_for_cache = (
            seat.get("code")
            or seat.get("seatCode")
            or seat.get("id")
            or seat.get("seatId")
        )
        if seat_code_for_cache and expire_time_ms:
            try:
                LAST_SEAT_EXPIRE[str(seat_code_for_cache)] = int(expire_time_ms)
            except Exception:
                # 캐시 실패는 치명적이지 않으므로 무시
                pass

        confirm_time_str = format_time(confirm_time_ms) if confirm_time_ms else "알 수 없음"
        count_down_time_str = format_time(count_down_time_ms) if count_down_time_ms else "알 수 없음"
        enter_time_str = format_time(enter_time_ms) if enter_time_ms else "알 수 없음"
        expire_time_str = format_time(expire_time_ms) if expire_time_ms else "알 수 없음"

        # 상태 문자열 매핑: 예약 완료(입실 대기)와 이용 중을 구분해서 표시
        if state == 5 and enter_time_ms:
            status_str = "이용 중"
        elif state == 0 and enter_time_ms is None and out_time_ms is None:
            status_str = "입실 대기(예약 완료)"
        else:
            status_str = "퇴실 또는 종료"

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

            # keyring에 저장된 정보가 없으면 로그인 마법사로 입력받기
            if not creds:
                creds = _login_wizard()

            if creds:
                std_id, password = creds
                cookie = _get_or_login_cookie(std_id, password)

                if cookie and not from_keyring:
                    # 처음 로그인에 성공한 경우 자격 증명 저장
                    _save_credentials(std_id.strip(), password)
                    typer.secho(
                        "자동 로그인 성공! 아이디와 비밀번호를 안전하게 저장했습니다.",
                        fg=typer.colors.GREEN,
                    )
                elif cookie and from_keyring:
                    typer.secho(
                        f"저장된 학번({std_id})으로 자동 로그인되었습니다.",
                        fg=typer.colors.GREEN,
                    )
                else:
                    typer.secho(
                        "자동 로그인 실패: 아이디 또는 비밀번호가 올바르지 않습니다.",
                        fg=typer.colors.RED,
                    )
            else:
                # 사용자가 마법사를 취소한 경우 등
                typer.secho(
                    "자동 로그인을 건너뛰고 메뉴로 이동합니다.",
                    fg=typer.colors.YELLOW,
                )
        except KeyboardInterrupt:
            typer.secho("\n자동 로그인이 취소되었습니다.", fg=typer.colors.YELLOW)
        except Exception as e:
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
        LOGGER.info("seats command called")
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

            if res.status_code != 200:
                typer.secho(f"[{room_name}] 조회 실패 ({res.status_code})", fg=typer.colors.RED)
                continue

            data = res.json().get("data", [])
            total = len(data)
            available = sum(1 for s in data if s.get("seatTime") is None)
            available_percent = (available / total) * 100 if total > 0 else 0.0
            LOGGER.info(
                f"seats room={room_name}, total={total}, available={available}, available_percent={available_percent:.1f}"
            )
            typer.echo(f"[{room_name}] {available:>4} / {total:<4} ({int(round(available_percent))}%)")

    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"좌석 정보를 불러오는 중 오류가 발생했습니다: {e}", fg=typer.colors.RED)

def _pick_seat(cookie: str) -> Optional[str]:
    """열람실을 먼저 고르고, 해당 열람실의 *빈 좌석* 목록에서 좌석을 선택해 seatId를 반환합니다."""
    # 1) 열람실 선택
    room_choice = inquirer.select(
        message="어느 열람실에서 예약할까요?",
        choices=[f"{rid} — {name}" for rid, name in ROOMS.items()],
        qmark="[?]",
        pointer=">",
    ).execute()
    LOGGER.info(f"_pick_seat room_choice: {room_choice}")
    try:
        room_id = int(room_choice.split(" — ")[0])
        LOGGER.info(f"_pick_seat parsed room_id: {room_id}")
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
        LOGGER.info(f"_pick_seat seats_data_len: {len(seats_data)}")
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
    LOGGER.info(f"_pick_seat available_count: {len(available)}")
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
        LOGGER.info(f"_pick_seat parse failure, picked={picked}")
        return None
    seat_id = m.group(1)
    LOGGER.info(f"_pick_seat picked={picked}, seat_id={seat_id}")
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
    LOGGER.info(f"_pick_seat_by_number room_choice: {room_choice}")
    try:
        room_id = int(room_choice.split(" — ")[0])
        LOGGER.info(f"_pick_seat_by_number parsed room_id: {room_id}")
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
        LOGGER.info(f"_pick_seat_by_number seats_data_len: {len(seats_data)}")
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
    LOGGER.info(f"_pick_seat_by_number user_input seat_no={seat_no}")

    # 4) 현재 예약 가능한 좌석 중에서 번호 일치하는 좌석 찾기
    available = [s for s in seats_data if s.get("seatTime") is None]
    LOGGER.info(f"_pick_seat_by_number available_count: {len(available)}")

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
            try:
                LOGGER.info(
                    "_pick_seat_by_number seat_no=%s exists but not available: %s",
                    seat_no,
                    json.dumps(seat_obj, ensure_ascii=False),
                )
            except Exception:
                LOGGER.info(
                    "_pick_seat_by_number seat_no=%s exists but not available (json dump failed)",
                    seat_no,
                )
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
            LOGGER.info(
                "_pick_seat_by_number seat_no=%s not found in seats_data", seat_no
            )
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
    LOGGER.info(f"_pick_seat_by_number resolved seat_no={seat_no}, seat_id={seat_id_str}")
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
        LOGGER.info("reserve command called")
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
        LOGGER.info(f"reserve mode: {mode}")

        if mode == "열람실에서 선택":
            seat_id = _pick_seat(cookie) or ""
        else:
            # 열람실을 선택한 뒤, 사용자가 보는 좌석 번호(예: 76)를 입력받아 seatId를 해석한다.
            seat_id = _pick_seat_by_number(cookie) or ""

        LOGGER.info(f"reserve seat_id raw: {seat_id}")

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
        LOGGER.info(f"reserve minutes: {minutes}")

        res = requests.post(
            "https://libseat.khu.ac.kr/libraries/seat",
            headers={
                "Cookie": cookie,
                "User-Agent": _ua(),
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={"seatId": seat_id, "time": minutes},
            verify=False,
        )

        LOGGER.info(f"reserve response status: {res.status_code}")
        LOGGER.info(f"reserve response text: {res.text[:2000]}")

        try:
            data = res.json()
        except Exception:
            typer.secho("응답 파싱 실패. 서버 응답:", fg=typer.colors.RED)
            typer.echo(res.text)
            raise typer.Exit(1)

        code = data.get("code")
        msg = data.get("msg") or data.get("message") or ""
        LOGGER.info(f"reserve parsed response: code={code}, msg={msg}")

        # LibSeat 응답 의미:
        # - code == 1   : 정상적으로 좌석 사용 시작(또는 예약) 성공
        # - 그 외 숫자  : 에러 코드 (이미 사용 중, 시간 제한, 권한 부족 등)
        success = (code == 1)

        if success:
            typer.secho("좌석 예약/사용 시작 성공!", fg=typer.colors.GREEN, bold=True)
            typer.echo(f"seatId={seat_id}, time={minutes}분")
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
                # 이전에 확인한 예약 종료 시각이 있다면, 남은 시간을 계산해서 안내한다.
                try:
                    expire_ms = LAST_SEAT_EXPIRE.get(str(seat_id))
                except Exception:
                    expire_ms = None
                if expire_ms:
                    now_ms = int(time.time() * 1000)
                    if expire_ms > now_ms:
                        remaining_ms = expire_ms - now_ms
                        remaining_min = int(remaining_ms / 60_000)
                        if remaining_min < 1:
                            remaining_min = 1
                        expire_str = datetime.fromtimestamp(expire_ms / 1000).strftime("%Y-%m-%d %H:%M")
                        typer.secho(
                            f"이 좌석의 기존 예약은 {expire_str}에 종료됩니다. "
                            f"약 {remaining_min}분 후부터 다시 예약할 수 있습니다.",
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
        typer.secho(f"좌석 예약 중 오류가 발생했습니다: {e}", fg=typer.colors.RED)

@app.command()
def whoami() -> None:
    """키링에 저장된 기본 학번을 확인합니다."""
    pair = _get_credentials()
    if not pair:
        typer.secho("저장된 로그인 정보가 없습니다. `libgo login`을 실행하세요.", fg=typer.colors.YELLOW)
        raise typer.Exit(1)
    std_id, pw = pair
    typer.echo(f"현재 기본 학번: {std_id}")
    typer.echo("비밀번호: 저장됨" if pw else "비밀번호: (없음)")

@app.command()
def logout() -> None:
    """키링에 저장된 학번/비밀번호를 삭제합니다."""
    if _delete_credentials():
        typer.secho("저장된 로그인 정보를 삭제했습니다.", fg=typer.colors.GREEN)
    else:
        typer.secho("저장된 로그인 정보가 없습니다.", fg=typer.colors.YELLOW)

    global SESSION_COOKIE
    SESSION_COOKIE = None

def main() -> None:
    app()

def _perform_login(std_id: str, password: str) -> Optional[str]:
    LOGGER.info(f"_perform_login called for std_id={std_id}")
    try:
        session = requests.Session()

        # 1. 공개키 가져오기
        res = session.get(
            "https://lib.khu.ac.kr/login",
            headers={"User-Agent": _ua()},
            verify=False,
        )
        cookie = res.headers.get("Set-Cookie", "")
        match = re.search(r"encrypt\.setPublicKey\('([^']+)'", res.text)
        if not match:
            typer.secho("공개키를 가져올 수 없습니다.", fg=typer.colors.RED)
            return None

        pub_key = match.group(1)
        rsa_key = RSA.importKey(f"-----BEGIN PUBLIC KEY-----\n{pub_key}\n-----END PUBLIC KEY-----")
        cipher = PKCS1_v1_5.new(rsa_key)
        enc_id = base64.b64encode(cipher.encrypt(std_id.encode())).decode()
        enc_pw = base64.b64encode(cipher.encrypt(password.encode())).decode()

        # 2. 중앙도서관 로그인
        res = session.post(
            "https://lib.khu.ac.kr/login",
            data={"encId": enc_id, "encPw": enc_pw, "autoLoginChk": "N"},
            headers={"Cookie": cookie, "User-Agent": _ua()},
            verify=False,
            allow_redirects=True,
        )
        # 로그인 실패 여부는 호출한 쪽에서 메시지를 출력하도록, 여기서는 단순히 실패만 반환
        if '<p class="userName">' not in res.text:
            LOGGER.info("_perform_login failed: userName marker not found in response HTML")
            return None

        lib_cookie = "; ".join([f"{k}={v}" for k, v in session.cookies.get_dict().items()])

        # 3. mid_user_id 가져오기
        res_mid = session.get(
            "https://lib.khu.ac.kr/relation/mobileCard",
            headers={"Cookie": lib_cookie, "User-Agent": _ua()},
            verify=False,
        )
        match_mid = re.search(r'name="mid_user_id" value="([^"]+)"', res_mid.text)
        if not match_mid:
            typer.secho("❌ mid_user_id를 가져올 수 없습니다.", fg=typer.colors.RED)
            return None
        mid_user_id = match_mid.group(1)

        # 4. LibSeat 로그인
        seat_res = session.post(
            "https://libseat.khu.ac.kr/login_library",
            data={"STD_ID": std_id},
            headers={"Cookie": lib_cookie, "User-Agent": _ua()},
            verify=False,
            allow_redirects=False,
        )

        libseat_cookie = seat_res.headers.get("Set-Cookie")

        if not libseat_cookie:
            typer.secho(f"❌ LibSeat 로그인 실패 (상태 코드 {seat_res.status_code}) — 쿠키 없음", fg=typer.colors.RED)
            return lib_cookie

        combined_cookie = f"{lib_cookie}; {libseat_cookie}"
        LOGGER.info("_perform_login success (cookies acquired)")
        return combined_cookie

    except Exception as e:
        typer.secho(f"로그인 요청 중 오류 발생: {e}", fg=typer.colors.RED)
        return None

if __name__ == "__main__":
    main()
@app.command()
def leave() -> None:
    """현재 이용 중인 좌석을 퇴실 처리합니다."""
    try:
        LOGGER.info("leave command called")
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

        LOGGER.info(f"leave my-status raw: {json.dumps(data, ensure_ascii=False)[:1000]}")

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
        LOGGER.info(f"leave confirm={confirm}")
        if not confirm:
            typer.secho("퇴실을 취소했습니다.", fg=typer.colors.YELLOW)
            return

        # 2) 실제 퇴실 API 호출
        url = f"https://libseat.khu.ac.kr/libraries/leave/{seat_code}"
        leave_res = requests.post(
            url,
            headers={
                "Cookie": cookie,
                "User-Agent": _ua(),
                "Accept": "application/json",
            },
            verify=False,
        )

        LOGGER.info(f"leave response status={leave_res.status_code}")
        LOGGER.info(f"leave response text={leave_res.text[:2000]}")

        success = False
        msg = ""
        code = None

        try:
            body = leave_res.json()
            code = body.get("code")
            msg = body.get("msg") or body.get("message") or ""
            if code == 1:
                success = True
        except Exception:
            # JSON 응답이 아닐 경우 HTTP 상태 코드 기준으로만 성공 여부 판정
            if 200 <= leave_res.status_code < 300:
                success = True

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
        typer.secho(f"퇴실 처리 중 오류가 발생했습니다: {e}", fg=typer.colors.RED)