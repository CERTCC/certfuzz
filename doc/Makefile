EPYDOC=/opt/local/bin/epydoc-2.7
EPYDOC_CFG=./epydoc.conf

doc: html pdf

html:
	${EPYDOC} --config=${EPYDOC_CFG} --html --output=html
	
pdf:
	${EPYDOC} --config=${EPYDOC_CFG} --pdf --output=pdf
	
# text:
# 	${EPYDOC} --config=${EPYDOC_CFG} --text --output=text
	
check:
	${EPYDOC} --config=${EPYDOC_CFG} --check
	
	
