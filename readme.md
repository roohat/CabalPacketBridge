CabalPacketBridge
=================

This project showcases an extensible packet manipulation system for an online game.

CPB hooks the encryption and decryption functions in the game and allows plugins to modify and view incoming and outgoing packets in real time.

Plugins can be placed in a directory named "mod" inside the game executable's directory.

Plugin DLLs must export the following:

```C
void Initialize(void* injectSend);
void SendHook(void* socket, void* packet, int len);
void RecvHook(void* socket, void* packet, int len);
void Terminate();
```

Plugins may inject packets by calling the function pointer passed into Initialize. The function protorype is as follows:

```C
void InjectSend(void* socket, void* packet, int len);
```