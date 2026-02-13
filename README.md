# Web-Utility-Kit

Web Utility Kit – A popular toolkit that helps accurately and comprehensively test websites.

# Web-Utility-Kit

Web Utility Kit – A popular toolkit that helps accurately and comprehensively test websites.
tools.bctechvibe.io.vn/
│
├── client/ # Frontend (HTML/CSS/JavaScript)
│ ├── public/ # Static assets
│ │ ├── assets/
│ │ │ ├── images/
│ │ │ ├── vendor/
│ │ │ │ └── fontawesome/
│ │ │ └── fonts/
│ │ │ ├── BeVietNamPro/
│ │ │ └── Philosopher/
│ │ └── favicon.ico
│ │
│ ├── src/
│ │ ├── css/
│ │ │ ├── base/
│ │ │ │ ├── reset.css
│ │ │ │ ├── fonts.css
│ │ │ │ ├── variables.css
│ │ │ │ ├── typography.css
│ │ │ │ └── animations.css
│ │ │ ├── layout/
│ │ │ │ ├── header.css
│ │ │ │ ├── footer.css
│ │ │ │ ├── grid.css
│ │ │ │ └── container.css
│ │ │ ├── components/
│ │ │ │ ├── button.css
│ │ │ │ ├── tool-card.css
│ │ │ │ ├── badge.css
│ │ │ │ ├── card.css
│ │ │ │ └── formControl.css
│ │ │ ├── utilities/
│ │ │ │ ├── spacing.css
│ │ │ │ └── helpers.css
│ │ │ └── main.css # Import all CSS
│ │ │
│ │ └── js/
│ │ ├── components/
│ │ │ └── theme-toggle.js
│ │ ├── utils/
│ │ │ ├── dom.js
│ │ │ ├── format.js
│ │ │ ├── geo.js
│ │ │ ├── index.js
│ │ │ ├── network.js
│ │ │ ├── org.js
│ │ │ └── url.js
│ │ └── pages/
│ │ ├── dns-lookup.page.js
│ │ ├── ssl-tools.page.js #import all ssl tools
│ │ ├── ssl
│ │ │ ├── checker.js
│ │ │ ├── csrdecoder.js
│ │ │ ├── cerdecoder.js
│ │ │ ├── keymatcher.js
│ │ │ └── converter.js
│ │ └── ...
│ │
│ └── views/ # HTML pages
│ ├── index.html # Homepage
│ └── tools/
│ ├── dns-lookup.html
│ ├── ssl-checker.html
│ ├── redirect-checker.html
│ ├── my-ip-address.html
│ ├── chmod-calculator.html
│ └── mixed-content.html
├── docs/
│ ├── API.md
│ ├── CONTRIBUTING.md
│ └── SETUP.md
├── server/
│ ├── dns-lookup-tool/
│ │ ├── cmd/
│ │ │ └── main.go
│ │ ├── internal/
│ │ │ ├── dns/
│ │ │ │ ├── blacklist.go
│ │ │ │ ├── config.go
│ │ │ │ ├── dnssec_record.go
│ │ │ │ ├── dnssec.go
│ │ │ │ └── query.go
│ │ │ ├── handlers/
│ │ │ │ └── handlers.go
│ │ │ └── models/
│ │ │ │ └── models.go
│ │ ├── pkg/
│ │ │ └── validator/
│ │ │ └── validator.go
│ │ ├── .env
│ │ ├── GeoLite2-ASN.mmdb
│ │ ├── GeoLite2-City.mmdb
│ │ ├── GeoLite2-Country.mmdb
│ │ ├── go.mod
│ │ └── go.sum
│ ├── ssl
│ │ ├── cmd
│ │ │ └── main.go
│ │ ├── internal
│ │ │ ├── config
│ │ │ │ └── config.go
│ │ │ ├── models
│ │ │ │ └── models.go
│ │ │ ├── platform
│ │ │ │ ├── breaker
│ │ │ │ │ └── breaker.go
│ │ │ │ ├── cache
│ │ │ │ │ └── memory.go
│ │ │ │ ├── context
│ │ │ │ │ └── timeout.go
│ │ │ │ ├── middleware
│ │ │ │ │ └── ratelimit.go
│ │ │ │ ├── shared
│ │ │ │ │ ├── errors.go
│ │ │ │ │ ├── http.go
│ │ │ │ │ ├── normalize.go
│ │ │ │ │ └── validator.go
│ │ │ │ └── worker
│ │ │ ├── router
│ │ │ │ └── router.go
│ │ │ └── tools
│ │ │ ├── cer
│ │ │ ├── checker
│ │ │ │ ├── checker.go
│ │ │ │ ├── cipher.go
│ │ │ │ ├── collect.go
│ │ │ │ ├── server.go
│ │ │ │ ├── fingerprint.go
│ │ │ │ ├── handlers.go
│ │ │ │ ├── request.go
│ │ │ │ ├── server.go
│ │ │ │ └── service.go
│ │ │ ├── conveter
│ │ │ ├── csr
│ │ │ └── key
│ │ ├── pkg
│ │ ├── go.mod
│ │ └── go.sum
│ └── ...
├── .gitignore
├── LICENSE
└── README.md

dns-lookup-tool/
├── cmd/
│ └── main.go
├── internal/
│ ├── dns/
│ │ ├── blacklist.go
│ │ ├── config.go
│ │ ├── dnssec_record.go
│ │ ├── dnssec.go
│ │ └── query.go
│ ├── handlers/
│ │ └── handlers.go
│ └── models/
│ └── models.go
├── logs/
│ ├── error.log
│ └── dns.log
├── bin/
│ └── dns-lookup
├── GeoLite2-ASN.mmdb
├── GeoLite2-City.mmdb
├── GeoLite2-Country.mmdb
├── go.mod
└── go.sum
