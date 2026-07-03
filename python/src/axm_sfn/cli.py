"""
axm-sfn spoke CLI.

Registered under `axm.spokes` so `axm sfn <command>` works when axm-core
is installed alongside this package.
"""
import sys
from pathlib import Path

import click


@click.group("sfn")
def sfn_group():
    """AXM SFN — sovereign fabrication node spoke."""


@sfn_group.command("compile")
@click.option("--db",      required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to the axm-edge hot buffer (buffer.db)")
@click.option("--session", required=True,
              help="Session ID to compile (hex string from the daemon log)")
@click.option("--key",     required=True, type=click.Path(exists=True, path_type=Path),
              help="Publisher secret key: a 3904-byte axm-hybrid1 blob "
                   "(from `axm sfn keygen` or `axm-build keygen`)")
@click.option("--out",     default="./shards", show_default=True,
              type=click.Path(path_type=Path),
              help="Output directory for compiled shards")
def compile_cmd(db: Path, session: str, key: Path, out: Path):
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
        )
        click.echo(f"✓  Shard compiled and verified: {shard_path}")
    except Exception as exc:
        click.echo(f"✗  {exc}", err=True)
        sys.exit(1)


@sfn_group.command("keygen")
@click.option("--out", default="./sfn-key.bin", show_default=True,
              type=click.Path(path_type=Path),
              help="Output path for the private key file")
def keygen_cmd(out: Path):
    """Generate an axm-hybrid1 publisher key for AXM SFN compilation.

    There is no default signing key anywhere in the toolchain; a signature
    under a published key proves integrity, never authenticity.
    """
    from axm_build.sign import hybrid1_keygen

    public_key, secret_key = hybrid1_keygen()   # 1344-byte pub, 3904-byte secret
    out.write_bytes(secret_key)
    pub_path = out.with_suffix(".pub")
    pub_path.write_bytes(public_key)
    click.echo(f"✓  Key:    {out}  (3904-byte axm-hybrid1 secret — keep offline)")
    click.echo(f"✓  Public: {pub_path}")
