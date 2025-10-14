// Package model - ProjectRelease defines the struct and handles marshaling/unmarshaling the struct to/from NFT Storage.
package model

import "time"

// ProjectRelease defines a Version of an Component for a List View
type ProjectRelease struct {
	Key                      string    `json:"_key,omitempty"`
	Cid                      string    `json:"cid,omitempty"`
	ObjType                  string    `json:"objtype,omitempty"`
	Name                     string    `json:"name"`
	Version                  string    `json:"version"`
	ProjectType              string    `json:"projecttype,omitempty"`
	Basename                 string    `json:"basename,omitempty"`
	BuildDate                time.Time `json:"builddate,omitempty"`
	BuildID                  string    `json:"buildid,omitempty"`
	BuildNum                 string    `json:"buildnum,omitempty"`
	BuildURL                 string    `json:"buildurl,omitempty"`
	DockerRepo               string    `json:"dockerrepo,omitempty"`
	DockerSha                string    `json:"dockersha,omitempty"`
	DockerTag                string    `json:"dockertag,omitempty"`
	GitBranch                string    `json:"gitbranch,omitempty"`
	GitBranchCreateCommit    string    `json:"gitbranchcreatecommit,omitempty"`
	GitBranchCreateTimestamp time.Time `json:"gitbranchcreatetimestamp,omitempty"`
	GitBranchParent          string    `json:"gitbranchparent,omitempty"`
	GitCommit                string    `json:"gitcommit,omitempty"`
	GitCommitAuthors         string    `json:"gitcommitauthors,omitempty"`
	GitCommittersCnt         string    `json:"gitcommittescnt,omitempty"`
	GitCommitTimestamp       time.Time `json:"gitcommittimestamp,omitempty"`
	GitContribPercentage     string    `json:"gitcontribpercentage,omitempty"`
	GitLinesAdded            string    `json:"gitlinesadded,omitempty"`
	GitLinesDeleted          string    `json:"gitlinesdeleted,omitempty"`
	GitLinesTotal            string    `json:"gitlinestotal,omitempty"`
	GitOrg                   string    `json:"gitorg,omitempty"`
	GitPrevCompCommit        string    `json:"gitpreviouscomponentcommit,omitempty"`
	GitRepo                  string    `json:"gitrepo,omitempty"`
	GitRepoProject           string    `json:"gitrepoproject,omitempty"`
	GitSignedOffBy           string    `json:"gitsignedoffby,omitempty"`
	GitTag                   string    `json:"gittag,omitempty"`
	GitTotalCommittersCnt    string    `json:"gittotalcommittescnt,omitempty"`
	GitURL                   string    `json:"giturl,omitempty"`
	GitVerifyCommit          bool      `json:"gitverifycommit,omitempty"`
}

// NewProjectRelease is the contructor that sets the appropriate default values
func NewProjectRelease() *ProjectRelease {
	return &ProjectRelease{ObjType: "ProjectRelease"}
}
