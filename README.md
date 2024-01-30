# SnowPass

Demo 

![snowpass_demo_video](./media/snowpass_demo_video.mkv)

## Table Of Contents
- [Features](#features)
- [Usage](#usage)


## Features

- Easy to use verbose syntax
- Cross platform 
- Standalone binary
- Copy to clipboard option

## Usage 

> Note: `sp` is a shorthand/alias for `snowpass`

<br />

Creating a password store, adding an entry and copying it to the clipboard

```bash
# create a keystore named 'work_secrets'
sp create work_secrets

# adds an entry to work_secrets
sp add github_token to work_secrets

# list all entries
sp list 

# get the data of the entry 
sp get github_token from work_secrets

# copy the data without printing it 
sp copy github_token from work_secrets
```

Editing, deleting and changing the password of a keystore or entries in a
keystore

```bash
sp list # listing all keystores and entries

# changing the password of the keystore 'work_secrets'
sp change-password work_secrets

# editing the contents of the 'github_token' in work_secrets
sp edit github_token from work_secrets

# deleting the github_token from work_secrets
sp delete github_token from work_secrets

# WARNING: THIS WILL DELETE THE ENTIRE KEYSTORE 
# ALONG WITH ALL THE ENTRIES IN IT
#
# IT WILL NOT ASK FOR CONFIRMATION AND NEITHER 
# WILL IT ASK FOR YOUR PASSWORD BEFORE DELETING IT
# 
sp delete-keystore work_secrets
```

Use `sp help` to display a detaied help list with examples.

[[ add the pic here]]


