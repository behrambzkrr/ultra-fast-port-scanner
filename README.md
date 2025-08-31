# Ultra Fast Port Scanner

Ultra Fast Port Scanner is a high-performance, multi-threaded TCP port scanner written in Python.  
It enables rapid scanning of IP addresses for open ports with optional banner grabbing and outputs results in JSON format.  
Ideal for network administrators and security professionals seeking speed and flexibility.

## Features

- Extremely fast multi-threaded scanning (up to 500 threads)
- Configurable port range and timeout
- Service name detection for common ports
- Optional banner grabbing
- Colorized and logged output
- Results saved as JSON

## Usage

```bash
python ultra_fast_port_scanner.py <target_ip> [options]
```

### Options

- `-p`, `--ports` Port range (default: 1-65535)  
  Example: `-p 1-1000`
- `-t`, `--threads` Number of threads (default: 200, max: 500)
- `--timeout` Connection timeout in seconds (default: 0.3)
- `-o`, `--output` Output file for results (default: scan_results.json)
- `--banner` Enable banner grabbing

### Example

```bash
python ultra_fast_port_scanner.py 192.168.1.1 -p 1-1000 -t 300 --timeout 0.3 --banner
```

## Notes

- Requires Python 3.6+
- Install dependencies:
  ```
  pip install colorama
  ```
- For the best performance, run on a machine with high network and CPU resources.

## License

This project is licensed under the MIT License with Attribution Requirement.  
**If you share, publish, or distribute this project or its derivatives, you must give credit to:  
Behram Bozkır ([behrambzkrr](https://github.com/behrambzkrr))**

See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for authorized network testing and educational purposes only.  
Unauthorized scanning of public or private networks may be illegal.
