FROM python
COPY ./CVEs_extractor.py /home
COPY ./requirements.txt /home
RUN pip3 install -r /home/requirements.txt
CMD python3 /home/CVEs_extractor.py