package dockerfile.security

deny[msg] {
 not user_defined
 msg := "Dockerfile must specify USER instruction"
}

user_defined {
 some i
 input[i].Cmd == "user"
}
