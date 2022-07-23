#!/usr/bin/env python3

import sys

from google.cloud import storage

def upload_blob(bucket_name, source_file_name, destination_blob_name):
    storage_client = storage.Client.from_service_account_json('upiso.json')
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)
    blob.upload_from_filename(source_file_name)
    print(f"File {source_file_name} uploaded to {destination_blob_name}.")

if __name__ == '__main__':
    try:
        filename = sys.argv[1]
        upload_blob('iso.hicloud.org', filename, filename)
    except Exception as e:
        print("filename error")
        print(e)