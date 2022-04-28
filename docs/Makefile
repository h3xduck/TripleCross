.PHONY: document.pdf all clean

all: document.pdf

document.pdf: document.tex
	latexmk -pdf -pdflatex="pdflatex -interaction=nonstopmode" -use-make document.tex

clean:
	latexmk -CA