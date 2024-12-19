
port=$1
ja=$2
jp=$3

echo "port" $port
echo "ja" $ja
echo "jp" $jp

# bash ./keygen.sh


ip=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n 1)


#  --progress=plain --no-cache

if [ -z "$jp" ] | [ -z "$ja" ]; 
then sudo docker build -t chord_server --build-arg PORT=$(echo $port) --build-arg IP="0.0.0.0" .; echo "no join";
else sudo docker build -t chord_server --build-arg IP="0.0.0.0" --build-arg PORT="$port" --build-arg JIP="$ja" --build-arg JPORT="$jp" .; echo "join"; fi

echo "ip:" "${ip}"
echo "port:" "${port}"
echo "ip:" "${ja}"
echo "port:" "${jp}"

sudo docker run -p "$port:$port" -d chord_server 
