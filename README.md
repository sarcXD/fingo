# Fingo - A handrolled go fintech server 

These are the remanants of a fintech server I was working on for a startup at a point in time. There is quite a lot of functionality, almost complete for a standard backend
server. The product itself was fairly interesting, a application to support fractionalizing government securities. I implemented everything myself, including a few things
that quite often are used from existing libraries.

## Features
- standard CRUD apis
- jwt token creation and authentication
- permission based api accesses
- non-orm postgresql queries
- transaction based queries
- automated error reporting via email
- automated email notifications for customer requests and actions
- standard cron jobs for automation
- a barebones docker containerization
- aws ec2 storage for assets
- data serialization
- https support
- standard password hashing
