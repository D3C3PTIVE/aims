find ./gen/ -print0 | while IFS= read -r -d '' file
do 
    if [[ $file == *.pb.go ]]; then
        echo "${file}"
        "${GOPATH}"/bin/protoc-go-inject-tag --input="${file}"
    fi
done
