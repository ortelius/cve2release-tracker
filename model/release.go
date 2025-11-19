// Package model - ProjectRelease defines the struct and handles marshaling/unmarshaling the struct to/from NFT Storage.
package model

import (
	"time"
)

// ProjectRelease defines a Version of an Component for a List View
type ProjectRelease struct {
	Key                      string    `json:"_key,omitempty"`
	Cid                      string    `json:"cid,omitempty"`
	ObjType                  string    `json:"objtype,omitempty"`
	Name                     string    `json:"name"`
	Version                  string    `json:"version"`
	ProjectType              string    `json:"projecttype,omitempty"`
	ContentSha               string    `json:"contentsha,omitempty"` // Git commit or Docker SHA for deduplication
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

	// OpenSSF Scorecard Results (https://github.com/ossf/scorecard)
	// Uses custom ScorecardAPIResponse struct that matches the API response format
	OpenSSFScorecardScore float64               `json:"openssf_scorecard_score,omitempty"` // Aggregate score 0-10
	ScorecardResult       *ScorecardAPIResponse `json:"scorecard_result,omitempty"`        // Complete result with all checks
}

// ScorecardAPIResponse represents the OpenSSF Scorecard API response
// This matches the structure returned by https://api.securityscorecards.dev/
type ScorecardAPIResponse struct {
	Date      string   `json:"date"`
	Repo      Repo     `json:"repo"`
	Scorecard Scores   `json:"scorecard"`
	Score     float64  `json:"score"`
	Checks    []Check  `json:"checks"`
	Metadata  []string `json:"metadata,omitempty"`
}

// Repo contains repository information
type Repo struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
}

// Scores contains scorecard version information
type Scores struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Check represents a single security check result
type Check struct {
	Name          string        `json:"name"`
	Score         int           `json:"score"`
	Reason        string        `json:"reason"`
	Details       []string      `json:"details,omitempty"`
	Documentation Documentation `json:"documentation"`
}

// Documentation provides information about a check
type Documentation struct {
	Short string `json:"short"`
	URL   string `json:"url"`
}

// NewProjectRelease is the contructor that sets the appropriate default values
func NewProjectRelease() *ProjectRelease {
	return &ProjectRelease{
		ObjType:               "ProjectRelease",
		OpenSSFScorecardScore: -1, // -1 indicates not yet assessed
	}
}
