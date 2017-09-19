#!/usr/bin/env python
"""module to generate a docx report based on osint findings"""

#https://python-docx.readthedocs.io/en/latest/user/text.html
#https://python-docx.readthedocs.io/en/latest/user/quickstart.html

import docx
from docx.shared import Pt
from docx.shared import RGBColor
from docx.shared import Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.shared import OxmlElement, qn

import time

class Reportgen():

    def run(self, args, reportDir, lookup, whoisResult, dnsResult, googleResult, shodanResult, pasteScrapeResult, harvesterResult, scrapeResult, credResult, pyfocaResult):

        today = time.strftime("%m/%d/%Y")
        for l in lookup:
            print '[+] Starting OSINT report for '+l

            #create a document 
            document = docx.Document()


            #add logo
            document.add_picture('./resources/logo.png', height=Inches(1.25))

            #add domain cover info

            paragraph = document.add_paragraph() 
            runParagraph = paragraph.add_run('%s' % l)
            font=runParagraph.font
            font.name = 'Arial'
            font.size = Pt(28)
            font.color.rgb = RGBColor(0x00,0x00,0x00)
        
            #add cover info
            paragraph = document.add_paragraph() 
            runParagraph = paragraph.add_run('Open Source Intelligence Report\n\n\n\n\n\n\n\n\n\n\n')
            font=runParagraph.font
            font.name = 'Arial'
            font.size = Pt(26)
            font.color.rgb = RGBColor(0xe9,0x58,0x23)

            paragraph = document.add_paragraph() 
            runParagraph = paragraph.add_run('Generated on: %s' % today)
            font=runParagraph.font
            font.name = 'Arial'
            font.size = Pt(16)
            font.color.rgb = RGBColor(0x00,0x00,0x00)


            #page break for cover page
            document.add_page_break()
            
            #add intro text on intropage

            heading = document.add_heading()
            runHeading = heading.add_run('Executive Summary')
            font=runHeading.font
            font.name = 'Arial'
            font.size = Pt(20)
            font.color.rgb = RGBColor(0xe9,0x58,0x23)

            paragraph = document.add_paragraph() 
            runParagraph = paragraph.add_run('\nThis document contains information about network, technology, and people associated with the assessment targets. The information was obtained by programatically querying various free or low cost Internet data sources.\n')
            font=runParagraph.font
            font.name = 'Arial'
            font.size = Pt(11)
            runParagraph = paragraph.add_run('\nThese data include information about the network, technology, and people associated with the targets.\n')
            font=runParagraph.font
            font.name = 'Arial'
            font.size = Pt(11)
            runParagraph = paragraph.add_run('\nSpecific data sources include: whois, domain name system (DNS) records, Google dork results, and data from recent compromises such as LinkedIn. Other sources include results from Shodan, document metadata from theHarvester and pyFoca, as well as queries to Pastebin, Github, job boards, etc. \n')
            font=runParagraph.font
            font.name = 'Arial'
            font.size = Pt(11)

            
            #page break for cover page
            document.add_page_break()

            heading = document.add_heading()
            runHeading = heading.add_run('Table of Contents')
            font=runHeading.font
            font.bold = True
            font.name = 'Arial'
            font.size = Pt(20)
            font.color.rgb = RGBColor(0x0,0x0,0x0)

            #TOC https://github.com/python-openxml/python-docx/issues/36
            paragraph = document.add_paragraph()
            run = paragraph.add_run()
            font.name = 'Arial'
            font.size = Pt(11)
            fldChar = OxmlElement('w:fldChar')  # creates a new element
            fldChar.set(qn('w:fldCharType'), 'begin')  # sets attribute on element

            instrText = OxmlElement('w:instrText')
            instrText.set(qn('xml:space'), 'preserve')  # sets attribute on element
            instrText.text = 'TOC \o "1-3" \h \z \u'   # change 1-3 depending on heading levels you need

            fldChar2 = OxmlElement('w:fldChar')
            fldChar2.set(qn('w:fldCharType'), 'separate')
            fldChar3 = OxmlElement('w:t')
            fldChar3.text = "Right-click to update field."
            fldChar2.append(fldChar3)

            fldChar4 = OxmlElement('w:fldChar')
            fldChar4.set(qn('w:fldCharType'), 'end')

            r_element = run._r
            r_element.append(fldChar)
            r_element.append(instrText)
            r_element.append(fldChar2)
            r_element.append(fldChar4)
            p_element = paragraph._p



            #page break for toc
            document.add_page_break()


            if credResult is not None:
                print '[+] Adding credential dump results to report'
                #header
                heading = document.add_heading(level=3)
                runHeading = heading.add_run('Credentials found from recent compromises (LinkedIn, Adobe, etc.) related to: %s' % l)
                font=runHeading.font
                font.name = 'Arial'
                font.color.rgb = RGBColor(0xe9,0x58,0x23)
                paragraph = document.add_paragraph()
                for c in credResult:
                    runParagraph = paragraph.add_run(''.join(c))
                    font=runParagraph.font
                    font.name = 'Arial'
                    font.size = Pt(11)
                document.add_page_break()
            
            #add whois data with header and break after end
            if whoisResult is not None:
                print '[+] Adding whois results to report'
                #header
                heading = document.add_heading(level=3)
                runHeading = heading.add_run('Whois Data for: %s' % l)
                font=runHeading.font
                font.name = 'Arial'
                font.color.rgb = RGBColor(0xe9,0x58,0x23)
                #content
                paragraph = document.add_paragraph()
                for line in whoisResult:
                    if ':' in line:
                        runParagraph = paragraph.add_run(''.join(line)+'\n')
                        font=runParagraph.font
                        font.name = 'Arial'
                        font.size = Pt(10)
                document.add_page_break()
            
            #add dns data with header and break after end
            if dnsResult is not None:
                print '[+] Adding DNS results to report'
                #header
                heading = document.add_heading(level=3)
                runHeading = heading.add_run('Domain Name System Data for: %s' % l)
                font=runHeading.font
                font.name = 'Arial'
                font.color.rgb = RGBColor(0xe9,0x58,0x23)
                #content
                paragraph = document.add_paragraph()
                for d in dnsResult:
                    runParagraph = paragraph.add_run('\n'.join(d))
                    font=runParagraph.font
                    font.name = 'Arial'
                    font.size = Pt(10)
                document.add_page_break()

            #google dork output
            if googleResult is not None:
                print '[+] Adding google dork results to report'
                #header
                heading = document.add_heading(level=3)
                runHeading = heading.add_run('Google Dork Results for: %s' % l)
                font=runHeading.font
                font.name = 'Arial'
                font.color.rgb = RGBColor(0xe9,0x58,0x23)
                #content
                paragraph = document.add_paragraph()
                for r in googleResult:
                    runParagraph = paragraph.add_run(''.join(r+'\n'))
                    font=runParagraph.font
                    font.name = 'Arial'
                    font.size = Pt(10)
                document.add_page_break()
            
            #harvester output
            if harvesterResult is not None:
                print '[+] Adding theHarvester results to report'
                #header
                heading = document.add_heading(level=3)
                runHeading = heading.add_run('theHarvester Results for: %s' % l)
                font=runHeading.font
                font.name = 'Arial'
                font.color.rgb = RGBColor(0xe9,0x58,0x23)
                #content
                paragraph = document.add_paragraph()
                for h in harvesterResult: 
                    runParagraph = paragraph.add_run(''.join(h))
                    #set font stuff
                    font=runParagraph.font
                    font.name = 'Arial'
                    font.size = Pt(10)
                document.add_page_break()
            

            #pastebin scrape output
            if pasteScrapeResult is not None:
                print '[+] Adding pastebin scrape results to report'
                document.add_heading('Pastebin URLs for %s' % l, level=3)
                document.add_paragraph(pasteScrapeResult)
                document.add_page_break()
                #document.add_paragraph(pasteScrapeContent)
                #document.add_page_break()



            #general scrape output
            if scrapeResult is not None:
                print '[+] Adding website scraping results to report'
                #header
                heading = document.add_heading(level=3)
                runHeading = heading.add_run('Website Scraping Results for %s' % l)
                font=runHeading.font
                font.name = 'Arial'
                font.color.rgb = RGBColor(0xe9,0x58,0x23)
                #content
                paragraph = document.add_paragraph()
                for sr in scrapeResult:
                    for line in sr:
                        runParagraph = paragraph.add_run(line)
                        font=runParagraph.font
                        font.name = 'Arial'
                        font.size = Pt(10)

                document.add_page_break()


            #pyfoca results
            if pyfocaResult is not None:
                print '[+] Adding pyfoca results to report'
                heading = document.add_heading(level=3)
                runHeading = heading.add_run('pyFoca Results for: %s' % l)
                font=runHeading.font
                font.name = 'Arial'
                font.color.rgb = RGBColor(0xe9,0x58,0x23)


                paragraph = document.add_paragraph()
                for fr in pyfocaResult:
                    #lolwut
                    runParagraph = paragraph.add_run(''.join(str(fr).strip(("\\ba\x00b\n\rc\fd\xc3"))))
                    font=runParagraph.font
                    font.name = 'Arial'
                    font.size = Pt(10)

                document.add_page_break()
            
            #shodan output
            if shodanResult is not None:
                heading = document.add_heading(level=3)
                runHeading = heading.add_run('Shodan Results for: %s' % l)
                font=runHeading.font
                font.name = 'Arial'
                font.color.rgb = RGBColor(0xe9,0x58,0x23)


                paragraph = document.add_paragraph()
                for shr in shodanResult:
                    try:
                        runParagraph = paragraph.add_run(str(shr).strip(("\\ba\x00b\n\rc\fd\xc3")))
                        #set font stuff
                        font=runParagraph.font
                        font.name = 'Arial'
                        font.size = Pt(10)
                    except:
                        print 'probably an encoding error...'
                        continue
            
            print '[+] Writing file: ./reports/%s/OSINT_%s_.docx'  % (l, l)
            document.save(reportDir+l+'/'+l+'OSINT_%s_.docx' % l)
