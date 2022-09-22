package utils

import (
	"os"
	"reflect"
)

func IsPathExist(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

func CreatDir(dirPath string) error {
	err := os.MkdirAll(dirPath, os.ModePerm)
	if err != nil {
		return err
	}
	err = os.Chmod(dirPath, 0777)
	if err != nil {
		return err
	}
	return nil
}

func ContainEx(a interface{}, f func(predicate interface{}) bool) bool {
	src := reflect.ValueOf(a)
	switch src.Kind() {
	case reflect.Slice, reflect.Array:
		count := src.Len()
		for i := 0; i < count; i++ {
			e := src.Index(i).Interface()
			if f(e) {
				return true
			}
		}
	default:
	}
	return false
}
