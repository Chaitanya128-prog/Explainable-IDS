import asyncio
import websockets

async def test():
    try:
        async with websockets.connect("ws://127.0.0.1:8002/ws/traffic") as ws:
            print("Connected successfully!")
            await asyncio.sleep(2)
            print("Still connected!")
    except Exception as e:
        print(f"Failed to connect: {e}")

asyncio.run(test())
