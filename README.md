# np-account-restore

Restore your PSN account configuration on a jailbroken PS4/PS5. This payload restores authentic `config.dat` and `auth.dat` from an activated console, writing the account configuration to the system registry.

> [!IMPORTANT]
> This could corrupt your user! Do not use if you have data at risk of being lost. Corrupting your user could result in a soft brick and will need to be factory restored in safe mode.

## Requirements

- A console that is signed in to PSN and activated (to extract files from)
- A jailbroken target console
- A way to send ELF payloads to the target console (e.g. netcat, payload sender)

## Step 1: Get the files

From a console signed in to PSN, extract these files:

```
/system_data/priv/home/<userid>/config.dat
/system_data/priv/home/<userid>/np/auth.dat
```

**PS4 only** — you also need:

```
/user/home/<userid>/np/account.dat
/user/home/<userid>/np/token.dat
```

`<userid>` is the hex user ID of the signed-in account.

## Step 2: Copy the files to the target console

Copy the files to the same paths on your jailbroken target console via FTP:

```
/system_data/priv/home/<userid>/config.dat
/system_data/priv/home/<userid>/np/auth.dat
```

**PS4 only** — also copy:

```
/user/home/<userid>/np/account.dat
/user/home/<userid>/np/token.dat
```



## Step 3: Send the payload

Send the appropriate ELF payload to the target console:

- **PS4:** `bin/np-restore-account-ps4.elf`
- **PS5:** `bin/np-restore-account-ps5.elf`

```bash
# Example using netcat
nc <console-ip> 9021 < bin/np-restore-account-ps4.elf
```

The payload reads `config.dat` for the foreground user and writes all account fields (username, online ID, account ID, email, country, language, etc.) to the system registry.

## Step 4: Reboot

Reboot the console. After reboot, your account will be restored.

## Building from source

Requires the [PS4 Payload SDK](https://github.com/ps4-payload-dev/pacbrew-packages) or [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk).

```bash
# Build both PS4 and PS5 ELFs
make

# Build PS4 only
make build-ps4

# Build PS5 only
make build-ps5

# Clean
make clean
```

## How it works

The payload:

1. Identifies the foreground user on the console
2. Reads `/system_data/priv/home/<userid>/config.dat`
3. Parses all account fields (username, account ID, email, online ID, NP environment, country, language, locale, and various flags)
4. Writes every field verbatim to the system registry via `sceRegMgrSet*`
5. No patching or modification — it purely copies existing `config.dat` data to the registry

## Credits

By **earthonion**
