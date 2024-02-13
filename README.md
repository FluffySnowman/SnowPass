# SnowPass

Demo 



https://github.com/FluffySnowman/SnowPass/assets/51316255/f64c8652-75ce-4fff-9218-31bcb5b58da3



## Table Of Contents
- [Features](#features)
- [Usage](#usage)
- [Installation](#installation)
  - [Linux](#linux)
  - [Windows](#windows)


## Features

- Easy to use verbose syntax
- Cross platform 
- Standalone binary
- Copy to clipboard option

## Installation

### Linux 

- Via curl

```bash
sudo curl -L -o /usr/local/bin/sp https://github.com/FluffySnowman/SnowPass/releases/download/v0.1.0/snowpass_linux_amd64 && sudo chmod +x /usr/local/bin/sp
```
- Via wget 

```bash
sudo wget -O /usr/local/bin/sp https://github.com/FluffySnowman/SnowPass/releases/download/v0.1.0/snowpass_linux_amd64 && sudo chmod +x /usr/local/bin/sp 
```

Open up a new shell and you should now be able to use the `sp` commad (make
sure that `/usr/local/bin` is in your `$PATH` [*which can be done by runinng
`echo $PATH`*])

### Windows 

- Via curl 

```bash
curl -o C:\Windows\System32\snowpass.exe https://github.com/FluffySnowman/SnowPass/releases/download/v0.2.0/snowpass_windows_x86_64.exe
```

<br />

#### Mac Installation not tested yet 


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


![help_list](https://github.com/FluffySnowman/SnowPass/assets/51316255/f77287ec-fb74-41c9-81dc-9b36541b29ff)



