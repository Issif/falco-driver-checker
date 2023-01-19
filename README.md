# falco-driver-checker

Check if your local system is compatible with latest versions of Falco and its drivers.

> /!\ This is just a POC, don't use it in production /!\

## Usage

`go run .`

## Output

```bash
+---------+------+------+
| VERSION | EBPF | KMOD |
+---------+------+------+
| 0.33.1  | ✓    | ✓   |
| 0.33.0  | ✓    | ✓   |
| 0.32.2  | ✓    | ✓   |
| 0.32.1  | ✓    | ✓   |
| 0.32.0  | ✓    | ✓   |
| 0.31.1  | ✓    | ✓   |
| 0.31.0  | ✓    | ✓   |
| 0.30.0  | x    | ✓    |
| 0.29.1  | x    | x    |
| 0.29.0  | x    | x    |
| 0.28.0  | x    | x    |
| 0.27.0  | x    | x    |
| 0.26.2  | x    | x    |
| 0.26.1  | x    | x    |
| 0.26.0  | x    | x    |
| 0.25.0  | x    | x    |
| 0.24.0  | x    | x    |
+---------+------+------+
```
