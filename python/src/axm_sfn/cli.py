"""
axm-sfn spoke CLI.

Registered under `axm.spokes` so `axm sfn <command>` works when axm-core
is installed alongside this package.
"""
import sys
from pathlib import Path

import click

from axm_build.sign import SUITE_ED25519, SUITE_MLDSA44


@click.group("sfn")
def sfn_group():
    """AXM SFN — sovereign fabrication node spoke."""


@sfn_group.command("compile")
@click.option("--db",      required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to the axm-edge hot buffer (buffer.db)")
@click.option("--session", required=True,
              help="Session ID to compile (hex string from the daemon log)")
@click.option("--key",     required=True, type=click.Path(exists=True, path_type=Path),
              help="Publisher key file (ML-DSA-44 sk||pk = 3840 B, or Ed25519 seed = 32 B)")
@click.option("--out",     default="./shards", show_default=True,
              type=click.Path(path_type=Path),
              help="Output directory for compiled shards")
@click.option("--suite",   default=SUITE_MLDSA44, show_default=True,
              type=click.Choice([SUITE_MLDSA44, SUITE_ED25519]),
              help="Signing suite")
def compile_cmd(db: Path, session: str, key: Path, out: Path, suite: str):
    """Compile a custody session into an AXM Layer 2 journal shard."""
    from axm_sfn.compile import compile_session

    private_key = key.read_bytes()
    out.mkdir(parents=True, exist_ok=True)

    click.echo(f"Compiling session {session} …")
    try:
        shard_path = compile_session(
            db_path=db,
            session_id=session,
            private_key=private_key,
            out_dir=out,
            suite=suite,
        )
        click.echo(f"✓  Shard compiled and verified: {shard_path}")
    except Exception as exc:
        click.echo(f"✗  {exc}", err=True)
        sys.exit(1)


@sfn_group.command("keygen")
@click.option("--out",   default="./sfn-key.bin", show_default=True,
              type=click.Path(path_type=Path),
              help="Output path for the private key file")
@click.option("--suite", default=SUITE_MLDSA44, show_default=True,
              type=click.Choice([SUITE_MLDSA44, SUITE_ED25519]),
              help="Signing suite")
def keygen_cmd(out: Path, suite: str):
    """Generate a publisher signing key for AXM SFN compilation."""
    if suite == SUITE_MLDSA44:
        from axm_build.sign import mldsa44_keygen
        kp = mldsa44_keygen()
        key_bytes = kp.secret_key + kp.public_key  # sk||pk = 3840 B for CompilerConfig
        pub_bytes = kp.public_key
    else:
        from nacl.signing import SigningKey
        sk = SigningKey.generate()
        key_bytes = bytes(sk)
        pub_bytes = bytes(sk.verify_key)

    out.write_bytes(key_bytes)
    pub_path = out.with_suffix(".pub")
    pub_path.write_bytes(pub_bytes)
    click.echo(f"✓  Key:    {out}")
    click.echo(f"✓  Public: {pub_path}")
