from __future__ import annotations
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from typing import Optional, Tuple
from datetime import datetime
import time

import typer
from InquirerPy import inquirer
import keyring
import json

app = typer.Typer(help="경희대 중앙도서관 CLI")

SERVICE = "libgo"  
ID_KEY = "default_id"    

MOBILE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
)

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

def _delete_credentials() -> None:
    try:
        std_id = keyring.get_password(SERVICE, ID_KEY)
        if std_id:
            try:
                keyring.delete_password(SERVICE, std_id)
            except keyring.errors.PasswordDeleteError:
                pass
        keyring.delete_password(SERVICE, ID_KEY)
        typer.secho("keyring에서 자격 증명을 삭제했습니다.", fg=typer.colors.GREEN)
    except Exception:
        typer.secho("keyring에서 자격 증명 삭제 실패 또는 자격 증명 없음.", fg=typer.colors.YELLOW)

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

        _save_credentials(std_id.strip(), password)
        typer.secho("아이디 비밀번호 저장 완료", fg=typer.colors.GREEN)
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
                    "로그아웃",
                    "나가기",
                ],
                default="로그인",
                qmark="[?]",
                pointer=">",
            ).execute()

            if choice == "로그인":
                creds = _get_credentials()
                if creds:
                    from_keyring = True
                else:
                    from_keyring = False
                    creds = _login_wizard()
                if creds:
                    std_id, password = creds
                    cookie = _perform_login(std_id, password)
                    if cookie:
                        if from_keyring:
                            typer.secho(f"이미 로그인되어 있습니다. (학번: {std_id})", fg=typer.colors.GREEN)
                        else:
                            typer.secho("로그인 성공! 아이디 비밀번호를 안전하게 저장했습니다.", fg=typer.colors.GREEN)
                    else:
                        typer.secho("로그인 실패: 아이디 또는 비밀번호가 올바르지 않습니다.", fg=typer.colors.RED)
                else:
                    typer.secho("저장된 로그인 정보가 없습니다.", fg=typer.colors.RED)
            elif choice == "내 좌석 정보":
                status()
            elif choice == "실시간 좌석 현황":
                seats()
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
        credentials = _get_credentials()
        if not credentials:
            typer.secho("로그인이 필요합니다. 먼저 로그인 메뉴에서 로그인하세요.", fg=typer.colors.YELLOW)
            raise typer.Exit(1)
        std_id, password = credentials
        cookie = _perform_login(std_id, password)
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

        my_seat = data.get("data", {}).get("mySeat")
        if not my_seat:
            typer.echo("현재 이용 중인 좌석이 없습니다.")
            return

        seat = my_seat.get("seat", {})
        seat_name = seat.get("name", "알 수 없음")
        group = seat.get("group", {})
        room_name = group.get("name", "알 수 없음")
        class_group = group.get("classGroup", {})
        campus_name = class_group.get("name", "알 수 없음")

        enter_time_ms = my_seat.get("inTime")
        expire_time_ms = my_seat.get("expireTime")
        state = my_seat.get("state")

        def format_time(ms: int) -> str:
            return datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M")

        enter_time_str = format_time(enter_time_ms) if enter_time_ms else "알 수 없음"
        expire_time_str = format_time(expire_time_ms) if expire_time_ms else "알 수 없음"
        status_str = "이용 중" if state == 5 else "퇴실 또는 종료"

        remaining_time_str = "알 수 없음"
        if expire_time_ms:
            remaining_minutes = int((expire_time_ms / 1000 - time.time()) / 60)
            if remaining_minutes < 0:
                remaining_minutes = 0
            remaining_time_str = f"{remaining_minutes}분"

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

        typer.secho(f"\n=== 📚 내 좌석 정보 ({now_str} 기준) ===", fg=typer.colors.CYAN, bold=True)
        lines = [
            f"캠퍼스     : {campus_name}",
            f"열람실     : {room_name}",
            f"좌석 번호  : {seat_name}",
            f"입실 시간  : {enter_time_str}",
            f"만료 시간  : {expire_time_str}",
            f"상태       : {status_str}",
            f"남은 시간  : {remaining_time_str}",
        ]

        for line in lines:
            typer.echo(line)

    except Exception as e:
        typer.secho("좌석 정보를 불러오는 중 오류가 발생했습니다.", fg=typer.colors.RED)

@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        menu()

@app.command()
def seats() -> None:
    """
    중앙도서관 열람실별 남은 좌석 수를 실시간으로 표시합니다.
    """
    try:
        credentials = _get_credentials()
        if not credentials:
            typer.secho("로그인이 필요합니다. 먼저 로그인 메뉴에서 로그인하세요.", fg=typer.colors.YELLOW)
            raise typer.Exit(1)

        std_id, password = credentials
        cookie = _perform_login(std_id, password)
        if not cookie:
            typer.secho("로그인 실패: 쿠키를 얻을 수 없습니다.", fg=typer.colors.RED)
            raise typer.Exit(1)

        rooms = {
            8: "1F 제1열람실",
            9: "2F 제2열람실",
            10: "1F      벗터",
            11: "2F      혜윰",
        }

        typer.secho("\n=== 🪑 실시간 열람실 좌석 현황 ===\n", fg=typer.colors.CYAN, bold=True)

        for room_id in [8, 10, 11, 9]:
            room_name = rooms[room_id]
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
            typer.echo(f"[{room_name}] {available:>4} / {total:<4} ({int(round(available_percent))}%)")

    except Exception as e:
        typer.secho(f"좌석 정보를 불러오는 중 오류가 발생했습니다: {e}", fg=typer.colors.RED)

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
    _delete_credentials()
    typer.secho("저장된 로그인 정보를 삭제했습니다.", fg=typer.colors.GREEN)

def main() -> None:
    app()

def _perform_login(std_id: str, password: str) -> Optional[str]:
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
        if '<p class="userName">' not in res.text:
            typer.secho("로그인 실패: 아이디 또는 비밀번호가 올바르지 않습니다.", fg=typer.colors.RED)
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
        return combined_cookie

    except Exception as e:
        typer.secho(f"로그인 요청 중 오류 발생: {e}", fg=typer.colors.RED)
        return None

if __name__ == "__main__":
    main()