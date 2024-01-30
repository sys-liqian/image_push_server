package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/docker/distribution/uuid"
	"github.com/mholt/archiver/v3"
	"github.com/opencontainers/go-digest"
)

const (
	manifestFilename = "manifest.json"
)

type Manifests = []Manifest

type Manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type Config struct {
	Address   string
	Username  string
	Password  string
	SkipTLS   bool
	ChunkSize int
	filePath  string
	tmpFolder string
}

type FileInfo struct {
	absolutePath string
	fileSize     int64
	digest       string
}

type Job interface {
	Run(*Config) error
}

type FileJob struct {
	repo   string
	info   *FileInfo
	client *http.Client
}

type ManifestJob struct {
	layerInfos         []*FileInfo
	manifestConfigInfo *FileInfo
	repo               string
	tag                string
	client             *http.Client
}

var (
	ErrInvalidRepoTag = errors.New("invalid repo tag")
)

func run(c *Config) error {
	defer os.RemoveAll(c.tmpFolder)

	// http client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.SkipTLS},
	}
	client := &http.Client{Transport: tr}

	manifests, err := parseManifestFile(c)
	if err != nil {
		return err
	}

	jobs := make([]Job, 0)
	for _, manifest := range manifests {
		for _, repoTag := range manifest.RepoTags {
			repo, tag, err := parseRepoTag(repoTag)
			if err != nil {
				log.Printf("paseRepoTag faild: %s", err)
				continue
			}

			// layers
			layerInfos := make([]*FileInfo, len(manifest.Layers))
			for k, layerPath := range manifest.Layers {
				fileinfo, err := getFileInfo(c, layerPath)
				if err != nil {
					return err
				}
				layerInfos[k] = fileinfo
				layerJob := &FileJob{
					repo:   repo,
					info:   fileinfo,
					client: client,
				}
				jobs = append(jobs, layerJob)
			}

			// contianer config
			fileinfo, err := getFileInfo(c, manifest.Config)
			if err != nil {
				return err
			}
			containerConfigJob := &FileJob{
				repo:   repo,
				info:   fileinfo,
				client: client,
			}
			jobs = append(jobs, containerConfigJob)

			// manifest
			manifestJob := &ManifestJob{
				layerInfos:         layerInfos,
				manifestConfigInfo: fileinfo,
				repo:               repo,
				tag:                tag,
				client:             client,
			}
			jobs = append(jobs, manifestJob)
		}
	}

	for _, v := range jobs {
		if err = v.Run(c); err != nil {
			return err
		}
	}
	return nil
}

func (j *FileJob) Run(c *Config) error {
	exist, err := j.Exist(c)
	if err != nil {
		return err
	}
	if exist {
		return nil
	}
	url := fmt.Sprintf("%s/v2/%s/blobs/uploads/", c.Address, j.repo)
	resp, err := j.client.Post(url, "", nil)
	if err != nil {
		return err
	}
	location := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusAccepted || location == "" {
		return fmt.Errorf("post %s failed, statusCode:%d", url, resp.StatusCode)
	}
	return j.Upload(c, location)
}

func (j *FileJob) Exist(c *Config) (bool, error) {
	url := fmt.Sprintf("%s/v2/%s/blobs/%s", c.Address, j.repo, j.info.digest)
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(c.Username, c.Password)
	resp, err := j.client.Do(req)
	if err != nil {
		return false, err
	}
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
}

func (j *FileJob) Upload(c *Config, url string) error {
	f, err := os.Open(j.info.absolutePath)
	if err != nil {
		return err
	}

	defer f.Close()
	contentSize := j.info.fileSize
	// Monolithic Upload
	if c.ChunkSize == 0 {
		url = fmt.Sprintf("%s&digest=%s", url, j.info.digest)
		contentLength := strconv.Itoa(int(j.info.fileSize))
		resp, err := j.DoUpload(c, http.MethodPut, url, contentLength, "", f)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("monolithic upload failed, response code: %d", resp.StatusCode)
		}
	} else {
		// Chunked Upload
		index, offset := 0, 0
		buf := make([]byte, c.ChunkSize)
		for {
			n, err := f.Read(buf)
			if err == io.EOF {
				break
			}
			offset = index + n
			index = offset
			chunk := buf[0:n]

			contentLength := strconv.Itoa(n)
			contentRange := fmt.Sprintf("%d-%d", index, offset)

			if int64(offset) == contentSize {
				url = fmt.Sprintf("%s&digest=%s", url, j.info.digest)
				resp, err := j.DoUpload(c, http.MethodPut, url, contentLength, contentRange, bytes.NewBuffer(chunk))
				if err != nil {
					return err
				}
				if resp.StatusCode != http.StatusCreated {
					return fmt.Errorf("chunked upload faild,response code: %d", resp.StatusCode)
				}
				break
			} else {
				resp, err := j.DoUpload(c, http.MethodPatch, url, contentLength, contentRange, bytes.NewBuffer(chunk))
				if err != nil {
					return err
				}
				location := resp.Header.Get("Location")
				if resp.StatusCode == http.StatusAccepted && location != "" {
					url = location
				} else {
					return fmt.Errorf("chunked upload faild,response code: %d", resp.StatusCode)
				}
			}
		}
	}

	return nil
}

func (j *FileJob) DoUpload(c *Config, method, url, contentLength, contentRange string, reader io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", contentLength)
	if contentRange != "" {
		req.Header.Set("Content-Range", contentRange)
	}
	log.Printf("%s %s", method, url)
	resp, err := j.client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (j *ManifestJob) Run(c *Config) error {
	manifest := &schema2.Manifest{}
	manifest.SchemaVersion = schema2.SchemaVersion.SchemaVersion
	manifest.MediaType = schema2.MediaTypeManifest
	manifest.Config.MediaType = schema2.MediaTypeImageConfig
	manifest.Config.Size = j.manifestConfigInfo.fileSize
	manifest.Config.Digest = digest.Digest(j.manifestConfigInfo.digest)
	for _, v := range j.layerInfos {
		item := distribution.Descriptor{
			MediaType: schema2.MediaTypeUncompressedLayer,
			Size:      v.fileSize,
			Digest:    digest.Digest(v.digest),
		}
		manifest.Layers = append(manifest.Layers, item)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", c.Address, j.repo, j.tag)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Content-Type", schema2.MediaTypeManifest)
	resp, err := j.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("put manifest failed, code is %d", resp.StatusCode)
	}
	return nil
}

func parseRepoTag(repo string) (string, string, error) {
	index := strings.Index(repo, "/")
	var repoAndTag string
	if index == -1 {
		repoAndTag = repo
	} else {
		repoAndTag = repo[index+1:]
	}
	arr := strings.Split(repoAndTag, ":")
	if len(arr) != 2 {
		return "", "", ErrInvalidRepoTag
	}
	return arr[0], arr[1], nil
}

func generateTmpFolder() (string, error) {
	path := filepath.Join("/tmp", uuid.Generate().String())
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return "", err
	}
	return path, nil
}

func parseManifestFile(c *Config) (Manifests, error) {
	if err := archiver.Unarchive(c.filePath, c.tmpFolder); err != nil {
		return nil, err
	}
	manifestFilePath := filepath.Join(c.tmpFolder, manifestFilename)
	data, err := os.ReadFile(manifestFilePath)
	if err != nil {
		return nil, err
	}
	manifests := make(Manifests, 0)
	if err = json.Unmarshal(data, &manifests); err != nil {
		return nil, err
	}
	return manifests, nil
}

func getFileInfo(c *Config, path string) (*FileInfo, error) {
	absolutePath := filepath.Join(c.tmpFolder, path)
	f, err := os.Open(absolutePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fileInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	hash := hex.EncodeToString(h.Sum(nil))
	return &FileInfo{
		absolutePath: absolutePath,
		fileSize:     fileInfo.Size(),
		digest:       fmt.Sprint("sha256:", hash),
	}, nil
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.FormValue("address") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer file.Close()

	skipTls := false
	skipTlsParam := r.FormValue("skipTls")
	if skipTlsParam != "" {
		skipTls, err = strconv.ParseBool(skipTlsParam)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	chunkSize := 0
	chunkSizeParam := r.FormValue("chunkSize")
	if chunkSizeParam != "" {
		chunkSize, err = strconv.Atoi(chunkSizeParam)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	tmpFolder, err := generateTmpFolder()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	localFile, err := os.Create(filepath.Join(tmpFolder, fileHeader.Filename))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer localFile.Close()

	_, err = io.Copy(localFile, file)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	c := &Config{
		Address:   r.FormValue("address"),
		Username:  r.FormValue("username"),
		Password:  r.FormValue("password"),
		SkipTLS:   skipTls,
		ChunkSize: chunkSize,
		filePath:  filepath.Join(tmpFolder, fileHeader.Filename),
		tmpFolder: tmpFolder,
	}

	if err = run(c); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func main() {
	http.HandleFunc("/upload", uploadHandler)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
