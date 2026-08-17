"""Command-line interface for the operational LNAT + ML-KEM hybrid profile.

The CLI intentionally avoids printing shared keys by default. Key material is
written to files with restrictive permissions where supported.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path
from typing import Iterable

from lnat_hybrid_kem import (
    HybridCiphertext,
    HybridPrivateKey,
    HybridPublicKey,
    LNATMLKEM768,
)
from lnat_params import ALL_PARAMS, DEFAULT_PARAMS, LNATParams

EXIT_OK = 0
EXIT_ERROR = 2


def _path(value: str | Path) -> Path:
    return value if isinstance(value, Path) else Path(value)


def _ensure_distinct(paths: Iterable[Path]) -> None:
    normalized = [path.expanduser().resolve(strict=False) for path in paths]
    if len(normalized) != len(set(normalized)):
        raise ValueError("input/output paths must be distinct")


def _preflight_outputs(paths: Iterable[Path], *, force: bool) -> None:
    for path in paths:
        if path.exists() and not force:
            raise FileExistsError(f"refusing to overwrite existing file: {path}")


def _atomic_write(path: Path, data: bytes, *, mode: int, force: bool) -> None:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite existing file: {path}")

    token = secrets.token_hex(8)
    temp = path.with_name(f".{path.name}.{os.getpid()}.{token}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(temp, flags, mode)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    except BaseException:
        try:
            temp.unlink(missing_ok=True)
        finally:
            raise


def _read(path: Path) -> bytes:
    return path.expanduser().read_bytes()


def _load_public(path: Path, params: LNATParams) -> HybridPublicKey:
    return HybridPublicKey.from_bytes(_read(path), params)


def _load_private(path: Path, params: LNATParams) -> HybridPrivateKey:
    return HybridPrivateKey.from_bytes(_read(path), params)


def _load_ciphertext(path: Path) -> HybridCiphertext:
    return HybridCiphertext.from_bytes(_read(path))


def keygen_files(
    kem: LNATMLKEM768,
    public_out: Path,
    private_out: Path,
    *,
    force: bool = False,
) -> tuple[HybridPublicKey, HybridPrivateKey]:
    public_out, private_out = _path(public_out), _path(private_out)
    _ensure_distinct([public_out, private_out])
    _preflight_outputs([public_out, private_out], force=force)
    pk, sk = kem.keygen()
    _atomic_write(private_out, sk.to_bytes(), mode=0o600, force=force)
    _atomic_write(public_out, pk.to_bytes(), mode=0o644, force=force)
    return pk, sk


def encap_files(
    kem: LNATMLKEM768,
    public_path: Path,
    ciphertext_out: Path,
    key_out: Path,
    *,
    force: bool = False,
) -> tuple[HybridCiphertext, bytes]:
    public_path = _path(public_path)
    ciphertext_out, key_out = _path(ciphertext_out), _path(key_out)
    _ensure_distinct([public_path, ciphertext_out, key_out])
    _preflight_outputs([ciphertext_out, key_out], force=force)
    pk = _load_public(public_path, kem.params)
    ct, key = kem.encap(pk)
    _atomic_write(key_out, key, mode=0o600, force=force)
    _atomic_write(ciphertext_out, ct.to_bytes(), mode=0o644, force=force)
    return ct, key


def decap_files(
    kem: LNATMLKEM768,
    public_path: Path,
    private_path: Path,
    ciphertext_path: Path,
    key_out: Path,
    *,
    force: bool = False,
) -> bytes:
    public_path, private_path = _path(public_path), _path(private_path)
    ciphertext_path, key_out = _path(ciphertext_path), _path(key_out)
    _ensure_distinct([public_path, private_path, ciphertext_path, key_out])
    _preflight_outputs([key_out], force=force)
    pk = _load_public(public_path, kem.params)
    sk = _load_private(private_path, kem.params)
    ct = _load_ciphertext(ciphertext_path)
    key = kem.decap(sk, pk, ct)
    _atomic_write(key_out, key, mode=0o600, force=force)
    return key


def selftest(kem: LNATMLKEM768) -> bool:
    pk, sk = kem.keygen()
    ct, sender = kem.encap(pk)
    receiver = kem.decap(sk, pk, ct)
    return sender == receiver and len(sender) == 32


def _profile(name: str) -> LNATParams:
    try:
        return ALL_PARAMS[name]
    except KeyError as exc:
        choices = ", ".join(sorted(ALL_PARAMS))
        raise ValueError(f"unknown profile {name!r}; choose one of: {choices}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lnat-pqc")
    parser.add_argument(
        "--profile",
        default=DEFAULT_PARAMS.name,
        choices=sorted(ALL_PARAMS),
        help="LNAT research profile used for hybrid post-processing",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="generate hybrid public/private keys")
    p_keygen.add_argument("--public-out", required=True, type=Path)
    p_keygen.add_argument("--private-out", required=True, type=Path)
    p_keygen.add_argument("--force", action="store_true")

    p_encap = sub.add_parser("encap", help="encapsulate to a public key")
    p_encap.add_argument("--public", required=True, type=Path)
    p_encap.add_argument("--ciphertext-out", required=True, type=Path)
    p_encap.add_argument("--key-out", required=True, type=Path)
    p_encap.add_argument("--force", action="store_true")

    p_decap = sub.add_parser("decap", help="decapsulate a ciphertext")
    p_decap.add_argument("--public", required=True, type=Path)
    p_decap.add_argument("--private", required=True, type=Path)
    p_decap.add_argument("--ciphertext", required=True, type=Path)
    p_decap.add_argument("--key-out", required=True, type=Path)
    p_decap.add_argument("--force", action="store_true")

    sub.add_parser("selftest", help="run a real KeyGen/Encap/Decap round trip")
    return parser


def run(argv: list[str] | None = None, *, kem: LNATMLKEM768 | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    params = _profile(args.profile)
    if kem is None:
        kem = LNATMLKEM768(params)
    elif kem.params != params:
        raise ValueError("injected KEM profile does not match --profile")

    if args.command == "keygen":
        pk, sk = keygen_files(kem, args.public_out, args.private_out, force=args.force)
        print(f"public-key-bytes={len(pk.to_bytes())}")
        print(f"private-key-bytes={len(sk.to_bytes())}")
        return EXIT_OK

    if args.command == "encap":
        ct, key = encap_files(
            kem,
            args.public,
            args.ciphertext_out,
            args.key_out,
            force=args.force,
        )
        print(f"ciphertext-bytes={len(ct.to_bytes())}")
        print(f"shared-key-bytes={len(key)}")
        return EXIT_OK

    if args.command == "decap":
        key = decap_files(
            kem,
            args.public,
            args.private,
            args.ciphertext,
            args.key_out,
            force=args.force,
        )
        print(f"shared-key-bytes={len(key)}")
        return EXIT_OK

    if args.command == "selftest":
        ok = selftest(kem)
        print(f"selftest={'PASS' if ok else 'FAIL'}")
        return EXIT_OK if ok else 1

    raise RuntimeError("unreachable command")


def main() -> None:
    try:
        raise SystemExit(run())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR) from exc


if __name__ == "__main__":
    main()
