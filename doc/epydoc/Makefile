EPYDOC=/opt/local/bin/epydoc-2.7
EPYDOC_CFG=./epydoc.conf
DOTPATH=/usr/local/bin/dot
RM=rm -rfv
HTML_DIR=./html
PDF_DIR=./pdf

doc: html

html:
	${EPYDOC} --config=${EPYDOC_CFG} --dotpath=${DOTPATH} --html --output=${HTML_DIR}
	
pdf:
	${EPYDOC} --config=${EPYDOC_CFG} --dotpath=${DOTPATH} --pdf --output=${PDF_DIR}
	
text:
	${EPYDOC} --config=${EPYDOC_CFG} --text
	
check:
	${EPYDOC} --config=${EPYDOC_CFG} --check
	
clean:
	${RM} ${HTML_DIR} ${PDF_DIR}
