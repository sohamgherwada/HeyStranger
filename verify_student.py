import sys
import face_recognition
import pytesseract
from PIL import Image

if len(sys.argv) != 4:
    print('Usage: python verify_student.py <student_id_path> <selfie_path> <school_name>')
    sys.exit(1)

student_id_path = sys.argv[1]
selfie_path = sys.argv[2]
school_name = sys.argv[3].lower()

# Load images
id_image = face_recognition.load_image_file(student_id_path)
selfie_image = face_recognition.load_image_file(selfie_path)

# Face encodings
id_faces = face_recognition.face_encodings(id_image)
selfie_faces = face_recognition.face_encodings(selfie_image)

if not id_faces or not selfie_faces:
    print('NOT VERIFIED')
    print('No face detected in one or both images.')
    sys.exit(0)

# Compare faces (use first face found in each)
match_results = face_recognition.compare_faces([id_faces[0]], selfie_faces[0])
face_match = match_results[0]

# OCR for school name
ocr_text = pytesseract.image_to_string(Image.open(student_id_path)).lower()
has_school = school_name in ocr_text

# Output
if face_match and has_school:
    print('VERIFIED')
else:
    print('NOT VERIFIED')
print(f'Face match: {face_match}, School found: {has_school}')
print('OCR text:', ocr_text) 