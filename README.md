# **evt**

<div align="center">

# **Email Verification Tool**

# **Go library for email verification without sending emails**

</div>

## **Install**

```
go get github.com/pchchv/evt
```

## **Usage**

```go
package main

import (
    "fmt"
    "github.com/pchchv/evt"
)

var verifier = evt.NewVerifier()

func main() {
    email := "example@exampledomain.com"
    ret, err := verifier.Verify(email)
    if err != nil {
        fmt.Println("verify email address failed, error is: ", err)
        return
    }
    if !ret.Syntax.Valid {
        fmt.Println("email address syntax is invalid")
        return
    }
    fmt.Println("email validation result", ret)
}
```

### Using SMTP

```go
package main

import (
    "fmt"
    "github.com/pchchv/evt"
)

var verifier = evt.NewVerifier().EnableSMTPCheck()

func main() {
    domain := "domain.org"
    username := "username"
    ret, err := verifier.CheckSMTP(domain, username)
    if err != nil {
        fmt.Println("check smtp failed: ", err)
        return
    }
    fmt.Println("smtp validation result: ", ret)
}
```

### Using SOCKS5

```go
package main

import (
    "fmt"
    "github.com/pchchv/evt"
)

var verifier = evt.NewVerifier().
    EnableSMTPCheck().
    Proxy("socks5://user:password@127.0.0.1:1080?timeout=5s")

func main() {
    domain := "domain.org"
    username := "username"
    ret, err := verifier.CheckSMTP(domain, username)
    if err != nil {
        fmt.Println("check smtp failed: ", err)
        return
    }
    fmt.Println("smtp validation result: ", ret)
}
```

### Checking whether a domain is disposable

```go
package main

import (
    "fmt"
    "github.com/pchchv/evt"
)

var verifier = evt.NewVerifier().EnableAutoUpdateDisposable()

func main() {
    domain := "domain.org"
    if verifier.IsDisposable(domain) {
        fmt.Printf("%s is a disposable domain\n", domain)
        return
    }
    fmt.Printf("%s is not a disposable domain\n", domain)
}
```

### Suggestions for domain typo

```go
package main

import (
    "fmt"
    "github.com/pchchv/evt"
)

var verifier = evt.NewVerifier()

func main() {
    domain := "gmai.com"
    suggestion := verifier.SuggestDomain(domain) 
    // suggestion should be `gmail.com`
    if suggestion != "" {
        fmt.Printf("domain %s is misspelled, right domain is %s. \n", domain, suggestion)
        return 
    }
    fmt.Printf("domain %s has no possible misspellings. \n", domain)
}
```
