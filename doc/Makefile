EPYDOC=/opt/local/bin/epydoc-2.7
EPYDOC_CFG=./epydoc.conf
DOTPATH=/usr/local/bin/dot

doc: html

html:
	${EPYDOC} --config=${EPYDOC_CFG} --dotpath=${DOTPATH} --html --output=html
	
pdf:
	${EPYDOC} --config=${EPYDOC_CFG} --dotpath=${DOTPATH} --pdf --output=pdf
	
text:
	${EPYDOC} --config=${EPYDOC_CFG} --text --output=text
	
check:
	${EPYDOC} --config=${EPYDOC_CFG} --check
	
	
