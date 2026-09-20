#!/bin/bash

echo "  Starting Termux Hub..."
PHP_CLI_SERVER_WORKERS=15 php -d upload_max_filesize=10G -d post_max_size=10G -d memory_limit=1G -d max_execution_time=0 -d max_input_time=0 -S 0.0.0.0:8080

echo "  Server is running in the background with 15 workers!"
