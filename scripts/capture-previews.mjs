import { chromium } from 'playwright';
const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
const page=await browser.newPage({viewport:{width:1440,height:1000},deviceScaleFactor:1});
page.on('pageerror',error=>console.error('Preview page error:',error.message));
async function selectTheme(name, font) {
 await page.getByRole('button',{name:'Настройки типографики',exact:true}).click();
 await page.getByRole('button',{name:new RegExp(name)}).click();
 if(font)await page.getByLabel('Гарнитура').selectOption(font);
 await page.getByRole('button',{name:'Закрыть настройки типографики',exact:true}).click();
 await page.evaluate(()=>document.fonts.ready);
 await page.waitForTimeout(250);
}
try{
 await page.goto('http://127.0.0.1:5173/',{waitUntil:'networkidle'});await page.evaluate(async()=>{await document.fonts.load('18px "Monaspace Neon"');await document.fonts.load('18px "Monaspace Krypton"');await document.fonts.ready;});
 const fonts=await page.evaluate(()=>({neon:document.fonts.check('18px "Monaspace Neon"'),krypton:document.fonts.check('18px "Monaspace Krypton"')}));
 if(!fonts.neon||!fonts.krypton)throw Error('Monaspace fonts not loaded');
 await page.getByRole('button',{name:'Кадр 57',exact:true}).waitFor();
 await selectTheme('Obsidian','neon');
 await page.getByRole('button',{name:'Кадр 23',exact:true}).click();
 await page.waitForTimeout(250);
 await page.screenshot({path:'previews/01-obsidian.png'});
 await selectTheme('Porcelain');await page.screenshot({path:'previews/02-porcelain.png'});
 await selectTheme('Obsidian');await page.keyboard.press('Control+Backquote');await page.getByTestId('native-terminal').waitFor({state:'visible'});await page.screenshot({path:'previews/04-console.png'});await page.keyboard.press('Control+Backquote');await page.getByTestId('native-terminal').waitFor({state:'hidden'});
 await page.locator('.editor-line-number[data-line="15"]').hover();await page.getByTestId('asm-preview').waitFor({state:'visible'});await page.waitForTimeout(200);await page.screenshot({path:'previews/06-assembly-hover.png'});await page.mouse.move(900,65);
 await page.setViewportSize({width:1024,height:768});await page.screenshot({path:'previews/05-compact.png'});
 await page.setViewportSize({width:1440,height:1000});await selectTheme('Spectral','krypton');
 await page.getByRole('button',{name:'Кадр 22',exact:true}).click();
 await page.getByRole('button',{name:'3D',exact:true}).click();
 await page.locator('.spatial-code__viewport canvas').waitFor({state:'visible'});
 await page.locator('.spatial-code__loading').waitFor({state:'hidden'});
 await page.waitForTimeout(1600);await page.screenshot({path:'previews/spectral.png'});
 console.log('phantom previews captured: editor frame 23, spatial calculation frame 22; fonts',fonts);
}catch(error){await page.screenshot({path:'/private/tmp/phantom-preview-error.png'});throw error;}finally{await browser.close()}
