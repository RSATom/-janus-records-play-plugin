# janus-play-plugin

## Build from sources
* Build and install Janus Gateway as described at https://github.com/meetecho/janus-gateway#compile
* `git clone https://github.com/RSATom/janus-play-plugin.git --recursive`
* `mkdir -p ./janus-play-plugin-build`
* `cd ./janus-play-plugin-build && cmake ../janus-play-plugin && make && make install`

## API

### `play` request

prepares recording with specific `id` to play

```
{
	"request" : "play",
	"id" : <unique ID of the recording to play>
}
```

Will result in a `preparing` status notification (JSEP offer will be attached):
```
{
	"play" : "preparing",
	"id" : <unique numeric ID of the recording>
}
```

### `start` request

starts playback (JSEP answer should be attached):

```
{
	"request" : "start"
}
```

Will result in a `playing` status:
```
{
	"play" : "playing"
}
```

### `stop` request

interrupts the playout process at any time, and tear the associated PeerConnection down:

```
{
	"request" : "stop"
}
```

Will result in a `stopped` status:
```
{
	"play" : "stopped"
}
```

### `done` event

If the plugin detects a loss of the associated PeerConnection, whether as a result of a `stop` request or file `EOF`/`EOS` found, a `done` result notification is triggered to inform the application the playout session is over:
```
{
	"play" : "done"
}
```
