# Installation

## Prerequisites

* `git`
* `gcc`
* `make`
* `cpanm`

## Step-by-step

1. Clone the repo
    ```
    curl -L https://cpanmin.us | perl - --sudo App::cpanminus
    git clone https://github.com/rlauer6/Amazon-Cognito-DecodeToken.git
    ```
2. Install dependencies
   ```
   cd Amazon-Cognito-DecodeToken.git
   for a in $(cat requires | awk '{print $1}'); do cpanm $a; done
   ```
3. Create a CPAN tarball
   ```
   make
   ```
4. Install using `cpanm`
   ```
   cpanm Amazon-Cognito-DecodeToken-0.01.tar.gz
   ```
