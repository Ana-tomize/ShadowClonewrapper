#!/usr/bin/env python3
import boto3
import os
from simple_term_menu import TerminalMenu

class AWSCleaner:
    def __init__(self):
        self.s3 = boto3.client('s3')

    def get_selection(self, title, options):
        menu = TerminalMenu(
            options,
            title=title,
            menu_cursor="→",
            menu_cursor_style=("fg_green", "bold"),
            menu_highlight_style=("bg_green", "fg_black"),
        )
        selected_index = menu.show()
        return None if selected_index is None else options[selected_index]

    def list_s3_folders(self, bucket):
        try:
            # Use set for unique folders
            folders = set()
            paginator = self.s3.get_paginator('list_objects_v2')
            
            for page in paginator.paginate(Bucket=bucket, Delimiter='/'):
                if 'CommonPrefixes' in page:
                    for prefix in page['CommonPrefixes']:
                        folders.add(prefix['Prefix'].rstrip('/'))
            
            return sorted(list(folders))
        except Exception as e:
            print(f"Error listing folders: {e}")
            return []

    def delete_s3_files(self, bucket, prefix):
        try:
            paginator = self.s3.get_paginator('list_objects_v2')
            delete_objects = []

            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                if 'Contents' not in page:
                    continue

                for obj in page['Contents']:
                    delete_objects.append({'Key': obj['Key']})

                    if len(delete_objects) >= 1000:
                        self.s3.delete_objects(
                            Bucket=bucket,
                            Delete={'Objects': delete_objects}
                        )
                        print(f"Deleted {len(delete_objects)} files...")
                        delete_objects = []

            if delete_objects:
                self.s3.delete_objects(
                    Bucket=bucket,
                    Delete={'Objects': delete_objects}
                )
                print(f"Deleted {len(delete_objects)} files...")

            return True
        except Exception as e:
            print(f"Error: {e}")
            return False

    def run(self):
        try:
            response = self.s3.list_buckets()
            buckets = [bucket['Name'] for bucket in response['Buckets']]
        except Exception as e:
            print(f"Error listing buckets: {e}")
            return

        bucket = self.get_selection("Select S3 Bucket:", buckets)
        if not bucket:
            return

        folders = self.list_s3_folders(bucket)
        if not folders:
            print("No folders found")
            return

        while True:
            folder = self.get_selection("Select folder (ESC to exit):", folders)
            if not folder:
                break

            if self.get_selection(f"Delete all files in {folder}?", ["Yes", "No"]) == "Yes":
                if self.delete_s3_files(bucket, f"{folder}/"):
                    print(f"Successfully deleted all files in {folder}")
                folders.remove(folder)

def main():
    try:
        AWSCleaner().run()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == '__main__':
    main()