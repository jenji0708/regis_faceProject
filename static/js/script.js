import React, { useState } from 'react';
import { View, Button, Image } from 'react-native';
import { launchCamera } from 'react-native-image-picker';

const Register = () => {
  const [photo, setPhoto] = useState(null);

  const handleTakePhoto = () => {
    launchCamera({}, (response) => {
      if (response.assets) {
        setPhoto(response.assets[0].uri);
      }
    });
  };

  const handleSubmit = async () => {
    const formData = new FormData();
    formData.append('image', {
      uri: photo,
      type: 'image/jpeg',
      name: 'photo.jpg',
    });

    const response = await fetch('http://your-backend-url/compare_face', {
      method: 'POST',
      body: formData,
    });

    const result = await response.json();
    alert(result.message);
  };

  return (
    <View>
      <Button title="Take Photo" onPress={handleTakePhoto} />
      {photo && <Image source={{ uri: photo }} style={{ width: 100, height: 100 }} />}
      <Button title="Submit" onPress={handleSubmit} />
    </View>
  );
};
