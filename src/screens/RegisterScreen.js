import React, { useState } from 'react';
import { View, Text, Button, Image, Alert } from 'react-native';
import { launchCamera, launchImageLibrary } from 'react-native-image-picker';

const CompareFaceScreen = () => {
  const [photo, setPhoto] = useState(null);

  // ฟังก์ชันสำหรับถ่ายรูป
  const handleTakePhoto = () => {
    launchCamera({}, (response) => {
      if (response.assets) {
        setPhoto(response.assets[0].uri);
      }
    });
  };

  // ฟังก์ชันสำหรับเลือกรูปจากแกลเลอรี่
  const handleChoosePhoto = () => {
    launchImageLibrary({}, (response) => {
      if (response.assets) {
        setPhoto(response.assets[0].uri);
      }
    });
  };

  // ฟังก์ชันสำหรับส่งข้อมูลไปที่เซิร์ฟเวอร์ Flask
  const handleSubmit = async () => {
    if (!photo) {
      Alert.alert('กรุณาเลือกรูปหรือถ่ายรูปก่อน');
      return;
    }

    const formData = new FormData();
    formData.append('image', {
      uri: photo,
      type: 'image/jpeg',
      name: 'photo.jpg',
    });

    try {
      const response = await fetch('http://your-backend-url/compare_face', {
        method: 'POST',
        body: formData,
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      const result = await response.json();
      Alert.alert(result.message);
    } catch (error) {
      console.error('Error:', error);
      Alert.alert('เกิดข้อผิดพลาดในการส่งข้อมูล');
    }
  };

  return (
    <View style={{ padding: 20 }}>
      <Text style={{ marginBottom: 20 }}>สแกนและเปรียบเทียบใบหน้า</Text>

      <Button title="ถ่ายรูป" onPress={handleTakePhoto} />
      <Button title="เลือกจากแกลเลอรี่" onPress={handleChoosePhoto} style={{ marginTop: 10 }} />

      {photo && (
        <Image
          source={{ uri: photo }}
          style={{ width: 200, height: 200, marginTop: 20 }}
        />
      )}

      <Button title="ตรวจสอบใบหน้า" onPress={handleSubmit} style={{ marginTop: 20 }} />
    </View>
  );
};

export default CompareFaceScreen;
