import xlsxwriter

class Report:

    def toExcel(vulnerabilities, fileName):
        workbook = xlsxwriter.Workbook(fileName + '.xlsx')
        worksheet = workbook.add_worksheet()

        #Colores
        LIGHT_GRAY = '#CCCCCC'

        #Formatos
        bold = workbook.add_format({'bold': True, 'bg_color': LIGHT_GRAY,'align': 'center'})
        align_center = workbook.add_format({'align': 'center','valign':'vcenter','text_wrap':True})
        align_text = workbook.add_format({'align': 'left','valign':'top','text_wrap':True})
        align_center_left = workbook.add_format({'valign':'vcenter','text_wrap':True})
        deep_red_format = workbook.add_format({'bg_color': '#860000'})
        red_format = workbook.add_format({'bg_color': '#FF0000'})
        yellow_format = workbook.add_format({'bg_color': 'yellow'})
        green_format = workbook.add_format({'bg_color': 'green'})
        formatCritical = {'type':'cell','criteria':'equal to','value':'"Critical"','format':deep_red_format}
        formatHigh = {'type':'cell','criteria':'equal to','value':'"High"','format':red_format}
        formatMedium = {'type':'cell','criteria':'equal to','value':'"Medium"','format':yellow_format}
        formatLow = {'type':'cell','criteria':'equal to','value':'"Low"','format':green_format}

        #headers
        column = 65 #'A'
        vuln = vulnerabilities[0]
        aux = {"host":'',"port":'',"protocol":'',"threat":''}
        aux.update(vuln)

        for i, key in enumerate(aux.keys()):
            worksheet.set_column(chr(column+i)+':'+chr(column+i),15,align_center_left)          
            worksheet.write(chr(column+i)+'1', key, bold)

        #Start from the second row
        row = 1
        col = 0

        for vuln in vulnerabilities:
            aux = {"host":'',"port":'',"protocol":'',"threat":''}
            aux.update(vuln)

            for i, value in enumerate(aux.values()):
                worksheet.write(row,col+i,value, align_text)


            #Risk formatting
            cell = 'D' + str(row+1)
            worksheet.conditional_format(cell,formatCritical)
            worksheet.conditional_format(cell,formatHigh)
            worksheet.conditional_format(cell,formatMedium)
            worksheet.conditional_format(cell,formatLow)

            row +=1

        workbook.close()