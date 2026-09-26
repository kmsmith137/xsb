"""Run the xsb CLI with a throwaway ~/.xsb and proxy runtime dir.

The integration tests run this as a subprocess instead of `xsb`, so they never
touch the user's real ~/.xsb or proxy. HOME stays real, so podman keeps its own
config and image store.

    python harness.py XSB_HOME RUNTIME_DIR VERB [args...]
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from xsb import cli                   # noqa: E402
from xsb.context import Context       # noqa: E402

if __name__ == "__main__":
    xsb_home, runtime_dir, *argv = sys.argv[1:]
    ctx = Context.from_process()
    ctx.xsb_home = xsb_home
    ctx.runtime_dir = runtime_dir
    sys.exit(cli.main(argv, ctx=ctx))
