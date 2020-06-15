flake_eval() {
  pip install flake8 > /dev/null; echo
  for py_file in *.py
  do
    echo "Flake8 output for: ${py_file}"
    echo '------------------------------'
    output=$(flake8 "${py_file}")
    [ -z "$output" ] && echo 'Everything correct!' || echo "$output"
    echo '------------------------------'; echo
  done
}

pylint_eval() {
  pip install pylint > /dev/null; echo
  for py_file in *.py
  do
    echo "Pylint output for: ${py_file}"
    echo '------------------------------'
    output=$(pylint --rcfile=.pylint.cfg "${py_file}")
    [ -z "$output" ] && echo 'Everything correct!' || echo "$output"
    echo '------------------------------'; echo
  done
}

mypy_eval() {
  pip install mypy > /dev/null; echo
  for py_file in *.py
  do
    echo "Mypy Type Checker output for: ${py_file}"
    echo '------------------------------'
    output=$(mypy "${py_file}")
    [ -z "$output" ] && echo 'Everything correct!' || echo "$output"
    echo '------------------------------'; echo
  done
}

unit_eval() {
  py=$1
  for py_file in *_test.py
  do
    echo "Unit test for: ${py_file}"
    echo '------------------------------'
    eval "$py -m unittest \"\${py_file}\""
    echo '------------------------------'; echo
  done
}

eval_all() {
  flake_eval
  pylint_eval
  mypy_eval
  unit_eval 'python3.8'
}

eval_all