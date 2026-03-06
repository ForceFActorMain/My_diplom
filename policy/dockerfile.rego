package dockerfile.security

################################
# 1. USER должен существовать
################################

deny[msg] {
 not user_defined
 msg := "Dockerfile must specify USER instruction"
}

user_defined {
 some i
 input[i].Cmd == "user"
}

################################
# 2. Не запускать контейнер от имени root
################################

deny[msg] {
 some i
 input[i].Cmd == "user"
 input[i].Value[0] == "root"
 msg := "Container must not run as root"
}

################################
# 3. Не использовать тег latest
################################

deny[msg] {
 some i
 input[i].Cmd == "from"
 contains(input[i].Value[0], ":latest")
 msg := "Avoid using latest tag in base image"
}

################################
# 4. Избегаем  инструкций ADD
################################

deny[msg] {
 some i
 input[i].Cmd == "add"
 msg := "Use COPY instead of ADD"
}

################################
# 5. Избегаем команды apt-get upgrade
################################

deny[msg] {
 some i
 input[i].Cmd == "run"
 contains(lower(concat(" ", input[i].Value)), "apt-get upgrade")
 msg := "Avoid apt-get upgrade in Dockerfile"
}

################################
# 6. Предотвращаем использование curl | bash
################################

deny[msg] {
 some i
 input[i].Cmd == "run"
 contains(lower(concat(" ", input[i].Value)), "curl")
 contains(lower(concat(" ", input[i].Value)), "| bash")
 msg := "Avoid curl piping directly to bash"
}

################################
# 7. Предотвращает использование wget | bash
################################

deny[msg] {
 some i
 input[i].Cmd == "run"
 contains(lower(concat(" ", input[i].Value)), "wget")
 contains(lower(concat(" ", input[i].Value)), "| bash")
 msg := "Avoid wget piping directly to bash"
}

################################
# 8. Предотвращает использование chmod 777
################################

deny[msg] {
 some i
 input[i].Cmd == "run"
 contains(lower(concat(" ", input[i].Value)), "chmod 777")
 msg := "Do not use chmod 777"
}

################################
# 9. Запрещает использование sudo
################################

deny[msg] {
 some i
 input[i].Cmd == "run"
 contains(lower(concat(" ", input[i].Value)), "sudo")
 msg := "Avoid using sudo in Dockerfile"
}

################################
# 10. Требует HEALTHCHECK
################################

deny[msg] {
 not healthcheck_defined
 msg := "Dockerfile must contain HEALTHCHECK"
}

healthcheck_defined {
 some i
 input[i].Cmd == "healthcheck"
}
