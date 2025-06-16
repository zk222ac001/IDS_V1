import logging
import sys

# Logging setup
def setup_log():
   logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("ids_log.txt", encoding="utf-8"),  # emoji-safe
        logging.StreamHandler(sys.stdout)  # may still fail with emojis on cp1252
    ]
)
