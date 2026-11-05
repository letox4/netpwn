"""Graba un preview de ~14 s de NetPwn en modo demo para LinkedIn.

Coreografia: Hosts (scan) -> fijar objetivo -> Puertos (scan en vivo)
-> Topologia (grafo) -> Wi-Fi (APs + consola en vivo) -> cierre en topologia.
"""
import asyncio
import pathlib
import sys

from playwright.async_api import async_playwright

OUT = pathlib.Path(__file__).parent / "docs" / "media"
OUT.mkdir(parents=True, exist_ok=True)
URL = "http://127.0.0.1:8123"


async def main() -> None:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(args=["--force-device-scale-factor=1"])
        ctx = await browser.new_context(
            viewport={"width": 1440, "height": 810},  # 16:9
            record_video_dir=str(OUT),
            record_video_size={"width": 1440, "height": 810},
            locale="en",
        )
        page = await ctx.new_page()
        await page.goto(URL)
        await page.wait_for_timeout(1200)

        # 1) Hosts: escanear red (los hosts caen con fingerprint de SO)
        await page.click("#btn-scan")
        await page.wait_for_timeout(2300)

        # 2) Puertos: scan en vivo (fila a fila) contra el host de la SCADA
        await page.click('.nav[data-panel="ports"]')
        await page.wait_for_timeout(400)
        await page.fill("#port-ip", "10.10.20.20")
        await page.click("#btn-portscan")
        await page.wait_for_timeout(2600)

        # 3) Topologia: mapear la red (grafo animado)
        await page.get_by_role("button", name="Topology").click()
        await page.click("#btn-topo-passive")
        await page.wait_for_timeout(3200)

        # 4) Wi-Fi: APs ya detectados por la linea de eventos + consola viva
        await page.get_by_role("button", name="Wi-Fi", exact=True).click()
        await page.wait_for_timeout(2600)

        # 5) Cierre: vuelta a la topologia
        await page.get_by_role("button", name="Topology").click()
        await page.wait_for_timeout(1600)

        video = page.video
        await ctx.close()  # cierra y finaliza el fichero de video
        path = await video.path()
        print(path)
        await browser.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
