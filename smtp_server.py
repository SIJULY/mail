import asyncio
from aiosmtpd.controller import Controller
from app import process_email_data

class CustomSMTPHandler:
    async def handle_DATA(self, server, session, envelope):
        print(f'收到邮件 from <{envelope.mail_from}> to <{envelope.rcpt_tos}>')
        for recipient in envelope.rcpt_tos:
            try:
                # 注意：这里我们假设 process_email_data 是一个同步函数
                # 在一个新线程中运行它以避免阻塞事件循环
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, process_email_data, recipient, envelope.content)
            except Exception as e:
                print(f"处理邮件时发生错误: {e}")
        return '250 OK'

if __name__ == '__main__':
    controller = Controller(CustomSMTPHandler(), hostname='0.0.0.0', port=25)
    print("SMTP 服务器正在启动，监听 0.0.0.0:25...")
    controller.start()
    print("SMTP 服务器已启动。按 Ctrl+C 关闭。")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print("正在关闭 SMTP 服务器...")
    finally:
        controller.stop()
