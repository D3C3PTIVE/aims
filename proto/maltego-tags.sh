find . -not -path "rpc*" -print0 | while IFS= read -r -d '' file
do 
    if [[ $file == *.pb.go ]]; then
        echo "${file}"
        $(which protoc-go-inject-tag) -input "${file}"
    fi
done
