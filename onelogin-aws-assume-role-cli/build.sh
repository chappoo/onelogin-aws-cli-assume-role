docker build --rm -f "./Dockerfile" -t onelogin-aws-cli:latest .
docker image save onelogin-aws-cli:latest -o onelogin-aws-cli.tar