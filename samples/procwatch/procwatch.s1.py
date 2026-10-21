import os

from typing import List, Optional, Tuple
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFType, BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


def _resolve_binary_path():
    # Installed layout keeps this script in ost/ and procwatch.<arch>.o in pe/
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(script_dir).lower() == "ost":
        return os.path.normpath(os.path.join(script_dir, "../pe"))
    return script_dir


class ProcWatchBOF(BaseBOFTask):
    def __init__(self):
        BaseBOFTask.__init__(
            self,
            "procwatch",
            base_binary_name="procwatch",
            base_binary_path=_resolve_binary_path(),
            bof_type=BOFType.ASYNC,
        )
        self.parser.description = "Report processes that start or exit. Runs as an async job until stopped."
        self.parser.add_argument("interval", nargs="?", type=int, default=2000, help="Poll interval in milliseconds (default 2000)")

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parsed = self.parser.parse_args(arguments)
        if parsed.interval <= 0:
            raise TaskInvalidArgumentsException("interval must be a positive number of milliseconds")
        return [(BOFArgumentEncoding.INT, parsed.interval)]

    def rewrite_response(self, response: Optional[str]) -> Optional[str]:
        # OC2 trims newlines at the edges of each async output chunk, so restore the break between chunks
        if response and self.get_out_name() == "exec_bof_async" and not response.startswith("Task started."):
            return "\n\n" + response
        return response
