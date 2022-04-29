import coloredlogs
import logging

logger = logging.getLogger("STEVE")
coloredlogs.install(fmt="[%(levelname)s] %(message)s (%(filename)s:%(lineno)d)", level=logging.DEBUG)#, logger=logger)
