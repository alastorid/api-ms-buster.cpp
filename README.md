# API-MS-Buster

The answer to all your `api-ms-` missing problems.

## How It Works
API-MS-Buster automatically repairs the PE import table to resolve all potential `api-ms-` not found errors. For technical details, refer to the source code.

## Usage

```sh
api-ms-buster.exe <your_exe_or_dll_in_problem>
```

## Important Notes
- Always **back up your file** before using API-MS-Buster.
- The tool modifies the PE import table, which **breaks the Authenticode signature** if present.
