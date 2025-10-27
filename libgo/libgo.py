from __future__ import annotations
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from typing import Optional, Tuple

import typer
from InquirerPy import inquirer
import keyring

app = typer.Typer(help="경희대 중앙도서관 CLI")

SERVICE = "khu-library"  
ID_KEY = "default_id"    

def _save_credentials(std_id: str, password: str) -> None:
    keyring.set_password(SERVICE, ID_KEY, std_id)
    keyring.set_password(SERVICE, std_id, password)

def _get_credentials() -> Optional[Tuple[str, Optional[str]]]:
    std_id = keyring.get_password(SERVICE, ID_KEY)
    if not std_id:
        return None
    pw = keyring.get_password(SERVICE, std_id)
    return std_id, pw

def _delete_credentials() -> None:
    try:
        std_id = keyring.get_password(SERVICE, ID_KEY)
        if std_id:
            try:
                keyring.delete_password(SERVICE, std_id)
            except keyring.errors.PasswordDeleteError:
                pass
        keyring.delete_password(SERVICE, ID_KEY)
    except keyring.errors.PasswordDeleteError:
        pass

def _login_wizard() -> None:
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
    except KeyboardInterrupt:
        typer.secho("\\nCancelled by user", fg=typer.colors.YELLOW)

@app.command()
def menu() -> None:
    """간단한 메뉴(UI 레퍼런스와 유사)"""
    try:
        choice = inquirer.select(
            message="메뉴 선택 (↕:이동, Enter:선택)",
            choices=[
                "로그인 설정",
                "나가기",
            ],
            default="로그인 설정",
            qmark="[?]",
            pointer=">",
        ).execute()

        if choice == "로그인 설정":
            _login_wizard()
        elif choice == "나가기":
            raise typer.Exit(0)
        else:
            typer.echo("아직 구현되지 않은 항목입니다.")
    except KeyboardInterrupt:
        typer.secho("\\nAborted!", fg=typer.colors.RED)

@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        menu()

@app.command()
def login(
    std_id: Optional[str] = typer.Option(None, "--id", "-i", help="학번(미지정 시 프롬프트)"),
) -> None:
    """
    학번/비밀번호로 중앙도서관에 로그인하고, 성공 시 키링에 저장합니다.
    로그인에 성공할 때까지 반복 입력을 지원합니다.
    """
    while True:
        try:
            if std_id is None:
                input_id = inquirer.text(
                    message="[중앙도서관] 학번을 입력하세요:",
                    qmark="[?]",
                    validate=lambda x: len(x.strip()) > 0 or "학번은 필수입니다.",
                ).execute()
            else:
                input_id = std_id
            password = inquirer.secret(
                message=f"[중앙도서관] 비밀번호 입력 (학번: {input_id}):",
                qmark="[?]",
                validate=lambda x: len(x) > 0 or "비밀번호는 필수입니다.",
            ).execute()
        except KeyboardInterrupt:
            typer.secho("\nCancelled by user", fg=typer.colors.YELLOW)
            raise typer.Exit(1)

        # Perform login
        cookie = _perform_login(input_id.strip(), password)
        if cookie:
            typer.secho("로그인 성공! 키링에 자격 증명이 저장되었습니다.", fg=typer.colors.GREEN)
            _save_credentials(input_id.strip(), password)
            raise typer.Exit(0)
        else:
            typer.secho("다시 시도하세요.", fg=typer.colors.YELLOW)
            std_id = None  # Always prompt for ID again after failure

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
        res = session.get("https://lib.khu.ac.kr/login", verify=False)
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
        res = session.post(
            "https://lib.khu.ac.kr/login",
            data={"encId": enc_id, "encPw": enc_pw, "autoLoginChk": "N"},
            headers={"Cookie": cookie, "User-Agent": "libgo/cli"},
            verify=False,
            allow_redirects=True,
        )
        if '<p class="userName">' not in res.text:
            typer.secho("로그인 실패: 아이디 또는 비밀번호가 올바르지 않습니다.", fg=typer.colors.RED)
            return None
        cookie_value = res.headers.get("Set-Cookie") or "; ".join(
            [f"{k}={v}" for k, v in session.cookies.get_dict().items()]
        )
        return cookie_value
    except Exception as e:
        typer.secho(f"로그인 요청 중 오류 발생: {e}", fg=typer.colors.RED)
        return None

if __name__ == "__main__":
    main()