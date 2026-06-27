# Guest WiFi rotation

This guide targets RouterOS v7.22.1 with the `wifi-qcom` stack. Do not use
legacy `/interface wireless` or `/caps-man` commands.

## Why profile-only rotation can fail

A WiFi interface may reference a named security profile and also contain its
own inline `security.passphrase`. The inline value wins. Updating only the
profile can therefore produce this failure:

- Telegram shows a new password and QR;
- the profile contains the new password;
- the radio still uses the old inline password.

NetSentry 0.3.0 removes this ambiguity by writing the same value to the named
profile and to every interface that references it. It then reads the profile
and every interface back. Any mismatch makes the rotation fail, and no success
QR is sent.

## Commands issued by NetSentry

Placeholders below are quoted RouterOS values. NetSentry escapes quoted values
before placing them in the command.

Set the named profile:

```routeros
/interface wifi security set [find name="<PROFILE>"] passphrase="<NEW_PASSWORD>"; :put OK
```

Discover all interfaces that reference it:

```routeros
:put [/interface wifi find where security="<PROFILE>"]
```

For each returned internal ID, read its name and set the inline password:

```routeros
:put [/interface wifi get <INTERFACE_ID> name]
/interface wifi set <INTERFACE_ID> security.passphrase="<NEW_PASSWORD>"; :put OK
```

Verify the hidden profile value:

```routeros
:put [/interface wifi security get [find name="<PROFILE>"] passphrase]
```

Verify the hidden inline value on each referencing interface:

```routeros
:put [/interface wifi get [find name="<INTERFACE_NAME>"] security.passphrase]
```

The `passphrase` fields are hidden from `print detail`; use `get` exactly as
shown. RouterOS `as-value` is intentionally not used.

## Manual pre-deploy inspection

From the Pi, discover IDs:

```bash
ssh -i <SSH_KEY> <ROUTER_USER>@<ROUTER_IP> \
  ':put [/interface wifi find where security="<PROFILE>"]'
```

For each ID, read the interface name. Then read the profile and interface
values separately:

```bash
ssh -i <SSH_KEY> <ROUTER_USER>@<ROUTER_IP> \
  ':put [/interface wifi security get [find name="<PROFILE>"] passphrase]'

ssh -i <SSH_KEY> <ROUTER_USER>@<ROUTER_IP> \
  ':put [/interface wifi get [find name="<INTERFACE_NAME>"] security.passphrase]'
```

Never paste the returned password into a ticket, commit, or shared log.

## Live verification after upgrade

1. Restart NetSentry and confirm the service is healthy.
2. Send `/rotate` from an allowed Telegram chat.
3. Confirm a success QR is returned.
4. Read the profile and every referencing interface with the commands above.
5. Confirm every value equals the password shown in Telegram.
6. Connect one test device using the QR.

If read-back fails, NetSentry sends a rotation-failed message. Treat the
password state as uncertain until the profile and every interface are checked.

## Troubleshooting

### QR password cannot connect

Read the profile and each interface. If the profile differs from an interface,
the inline shadow is active. On 0.3.0 this means the write or read-back failed;
check the service log for the target name and verify that the RouterOS SSH user
can set both `/interface wifi security` and `/interface wifi`.

### No interfaces are returned

Confirm `guest_wifi_rotator.security_profile` exactly matches the RouterOS
profile name and that the intended interfaces show that profile in their
`security` property. A deployment with no referencing interfaces can still
update and verify the profile, but it may not control the expected radio.

### Rotation reports failure but the profile changed

One interface write or read-back diverged. Do not use the new QR yet. Inspect
each target, correct RouterOS permissions or interface configuration, and run
`/rotate` again.

### `/guest` shows a value but clients still fail

`/guest` reads the profile. Verify inline interface values as well. `/rotate`
is the operation that synchronizes and verifies all targets.
