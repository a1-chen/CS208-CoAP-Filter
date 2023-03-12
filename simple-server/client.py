# client.py
import asyncio
import random
from aiocoap import *

async def main():
    context = await Context.create_client_context()
    alarm_state = random.choice([True, False])
    payload = b"OFF"

    if alarm_state:
        payload = b"ON"

    request = Message(code=PUT, payload=payload, uri="coap://[198.22.255.30]/alarm")

    response = await context.request(request).response
    #print('Result: %s\n%r'%(response.code, response.payload))
    print("payload: ", response.payload)
    print("mtype: ", response.mtype)
    print("code: ", response.code)
    print("opt: ", response.opt)
    print("mid: ", response.mid)
    print("token: ", response.token)
    print("remote: ", response.remote)
    print("request: ", response.request)

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())