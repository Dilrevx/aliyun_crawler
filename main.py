"""Project launcher.

Delegates to the unified CLI entrypoint so local runs and installed script
runs share exactly the same behavior.
"""

from aliyun_crawler.cli.app import main

if __name__ == "__main__":
    main()
